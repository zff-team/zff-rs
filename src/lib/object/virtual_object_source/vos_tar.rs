// - Parent
use super::*;
use crate::io::zffreader::ZffReader;

#[derive(Debug, Clone, PartialEq, Eq)]
struct VosEntry {
    file_header: FileHeader,
    payload: VosEntryPayload,
}

impl VosEntry {
    fn new(file_header: FileHeader, payload: VosEntryPayload) -> Self {
        Self {
            file_header,
            payload,
        }
    }

    fn update_payload(&mut self, payload: VosEntryPayload) {
        self.payload = payload;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VosEntryPayload {
    File(VosFileEntry),
    Directory(Vec<u64>), // contains the appropriate children
    Symlink(PathBuf), //contains the target path of the symlink
    HardLink(u64), //contains the filenumber to the linked file,
    SpecialFile(SpecialFileEncodingInformation), //contains the (merged) rdev and type
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
struct VosFileEntry {
    pub entry_start: u64, //start offset
    pub entry_len: u64,
}

impl VosFileEntry {
    fn new(entry_start: u64, entry_len: u64) -> Self {
        Self {
            entry_start,
            entry_len,
        }
    }
}

#[derive(Debug)]

pub struct VirtualObjectSourceLogicalTar<R: Read + Seek> {
    entries: BTreeMap<u64, VosEntry>, //filenumber, entry data
    zffreader: ZffReader<R>,
    hash_types: Vec<HashType>,
    signing_key_bytes: Option<Vec<u8>>,
}

impl<R: Read + Seek> VirtualObjectSourceLogicalTar<R> {
    pub fn new(
        mut zffreader: ZffReader<R>, 
        object_number: u64, 
        file_number: u64, 
        hash_types: Vec<HashType>, 
        signing_key_bytes: Option<Vec<u8>>) -> Result<Self> {
        zffreader.set_active_object(object_number)?;
        zffreader.set_active_file(file_number)?;
        let mut archive = Archive::new(zffreader);

        // to preserve all metadata stuff
        archive.set_unpack_xattrs(true);
        archive.set_preserve_mtime(true);
        archive.set_preserve_ownerships(true);
        archive.set_preserve_permissions(true);

        let mut vos_entries = BTreeMap::new();
        let mut root_dir_filenumbers = Vec::new();
        let mut directory_children = HashMap::<u64, Vec<u64>>::new(); //<file number of directory, Vec<filenumber of child>>
        let mut current_file_number = 0;
        let mut symlink_real_paths = HashMap::new();
        let mut parent_dir_filenumber_map = HashMap::new();
        let mut special_files_rdev_map = HashMap::new();
        let mut path_to_filenumber_map = HashMap::new();
        let mut hardlink_map = HashMap::new();

        for entry in archive.entries()? {
            current_file_number += 1;

            // Must be mutable to read the possibly stored
            // xattr's in pax_extensions() of entry.
            let mut entry = entry?;

            // to build the [FileHeader].
            let filetype = match entry.header().entry_type() {
                EntryType::Regular => FileType::File,
                EntryType::Link => FileType::Hardlink,
                EntryType::Symlink => FileType::Symlink,
                EntryType::Char => FileType::SpecialFile,
                EntryType::Block => FileType::SpecialFile,
                EntryType::Fifo => FileType::SpecialFile,
                EntryType::Directory => FileType::Directory,
                EntryType::Continuous => FileType::File,
                EntryType::GNULongName | EntryType::GNULongLink | EntryType::XHeader | EntryType::XGlobalHeader => return Err(ZffError::new(ZffErrorKind::Invalid, format!("{ERROR_TAR_PREPROCESSED_ENTRY}: {:?}", entry.header().entry_type()))),
                EntryType::GNUSparse => FileType::File,
                _ => return Err(ZffError::new(ZffErrorKind::Invalid, format!("{ERROR_TAR_PREPROCESSED_ENTRY}: {:?}", entry.header().entry_type()))),
            };
            match filetype {
                FileType::File | FileType::Directory | FileType::SpecialFile => {
                    // this map will be used by EntryType::Link (hardlinks), so the
                    // hardlinks can "linked" to the original data (see zff format specification)
                    // and be added to the hardlink_map.
                    let path = entry.path()?;
                    path_to_filenumber_map.insert(path.to_path_buf(), current_file_number);
                },
                _ => () //Symlinks and other hardlinks should not be added.
            }

            // This will merge the appropriate rdev major and rdev minor to a single rdev
            // value. The method should be equivalent to the libc makedev implementation.
            // This part is only necessary for special files. If major/minor rdev are not
            // given, the value will be just 0 for compatibility reasons with logical
            // filesystem dumps.
            if filetype == FileType::SpecialFile {
                let major = entry.header().device_major().ok().flatten().unwrap_or(0);
                let minor = entry.header().device_minor().ok().flatten().unwrap_or(0);
                let rdev = helper::makedev(major, minor);
                let special_file = match entry.header().entry_type() {
                    EntryType::Char => SpecialFileEncodingInformation::Char(rdev),
                    EntryType::Block => SpecialFileEncodingInformation::Block(rdev),
                    EntryType::Fifo => SpecialFileEncodingInformation::Fifo(rdev),
                    _ => unreachable!(), //should be handled before.
                };
                special_files_rdev_map.insert(current_file_number, special_file);
            }

            let path = entry.path()?;
            let filename = match path.file_name() {
                Some(filename) => filename,
                None => return Err(ZffError::new(ZffErrorKind::EncodingError, 
                    format!("{ERROR_TAR_ENCODING_ERROR_NO_FILENAME} {:?}", path)))
            }.into();

            // check if file path is root file
            let parent_filenumber = if check_root_path(path) {
                root_dir_filenumbers.push(current_file_number);
                0
            } else {
                // unwrap should be safe here
                // as we have already checked that the current file is 
                // not in root path.
                let path = entry.path()?;
                let parent_path = path.parent().unwrap();
                let parent_filenumber = match parent_dir_filenumber_map.get(&parent_path.to_path_buf()) { // check if the trailing separator is a problem.
                    Some(parent_filenumber) => *parent_filenumber,
                    None => return Err(ZffError::new(ZffErrorKind::EncodingError, 
                        format!("{ERROR_NOT_IN_MAP} {:?}", parent_path)))
                };

                directory_children.entry(parent_filenumber)
                .and_modify(|vec| vec.push(current_file_number))
                .or_insert(vec![current_file_number]);

                parent_filenumber
            };
            // if the filetype is a directory, it has potentially children.
            // Those children need to know the appropriate parent's filenumber.
            if filetype == FileType::Directory {
                let path = entry.path()?.into_owned();
                parent_dir_filenumber_map.insert(path, current_file_number);
            }
            if filetype == FileType::Symlink {
                let target = match entry.link_name() {
                    Ok(linkname_option) => match linkname_option {
                        Some(linkname_path) => linkname_path.to_path_buf(),
                        None => PathBuf::from(""),
                    },
                    Err(_) => PathBuf::from(""),
                };
                symlink_real_paths.insert(current_file_number, target);
            }
            if filetype == FileType::Hardlink {
                let target = match entry.link_name()? {
                    Some(linkname_path) => linkname_path.to_path_buf(),
                    None => return Err(ZffError::new(
                        ZffErrorKind::Invalid,
                        format!("{ERROR_TAR_MISSING_HARDLINK_TARGET} {:?}", entry.path()?.into_owned()),
                    )),
                };
                let hardlink_filenumber = match path_to_filenumber_map.get(&target) {
                    Some(filenumber) => *filenumber,
                    None => return Err(ZffError::new(ZffErrorKind::EncodingError, 
                        format!("{ERROR_NOT_IN_MAP} {:?}", target)))
                };
                hardlink_map.insert(current_file_number, hardlink_filenumber);
            }
            let entry_start_offset = entry.raw_file_position();
            let entry_size = entry.size();
            let fileheader = get_file_header_tar(&mut entry, filetype, filename, current_file_number, parent_filenumber)?;
            let vos_file_entry = VosFileEntry::new(entry_start_offset, entry_size);
            let vos_entry = VosEntry::new(fileheader, VosEntryPayload::File(vos_file_entry));
            vos_entries.insert(current_file_number, vos_entry);

        }

        //merge the whole stuff
        for (file_number, payload) in directory_children {
            if let Some(vos_entry) = vos_entries.get_mut(&file_number) {
                vos_entry.update_payload(VosEntryPayload::Directory(payload));
            }
        }
        for (file_number, payload) in symlink_real_paths {
            if let Some(vos_entry) = vos_entries.get_mut(&file_number) {
                vos_entry.update_payload(VosEntryPayload::Symlink(payload));
            }
        }
        for (file_number, payload) in special_files_rdev_map {
            if let Some(vos_entry) = vos_entries.get_mut(&file_number) {
                vos_entry.update_payload(VosEntryPayload::SpecialFile(payload));
            }
        }
        for (file_number, payload) in hardlink_map {
            if let Some(vos_entry) = vos_entries.get_mut(&file_number) {
                vos_entry.update_payload(VosEntryPayload::HardLink(payload));
            }
        }



        let zffreader = archive.into_inner();
        Ok(Self {
            entries: vos_entries,
            zffreader,
            hash_types,
            signing_key_bytes,
        })
    }
}

impl<R: Read + Seek> VirtualObjectSource for VirtualObjectSourceLogicalTar<R> {
    fn remaining_elements(&self) -> u64 {
        unimplemented!()
    }

    fn root_dir_filenumbers(&self) -> &Vec<u64> {
        unimplemented!()
    }
}

impl<R: Read + Seek> Iterator for VirtualObjectSourceLogicalTar<R> {
    type Item = Result<(FileHeader, VirtualFileFooterMetadata)>;

    fn next(&mut self) -> Option<Self::Item> {
        unimplemented!()
    }
}