// - Parent
use super::*;

use crate::footer::{VirtualFileExtent, VirtualFileMap};
use crate::io::zffreader::ZffReader;

#[derive(Debug, Clone, PartialEq, Eq)]
struct VosEntry {
    /// File header reconstructed from the tar entry metadata.
    file_header: FileHeader,
    /// Virtual payload description used to build the virtual file footer.
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
    /// Regular file data stored as a byte range inside the source tar file.
    File(VosFileEntry),
    /// Directory payload containing the file numbers of the directory children.
    Directory(Vec<u64>),
    /// Symbolic link payload containing the target path.
    Symlink(PathBuf),
    /// Hard link payload containing the file number of the link target.
    HardLink(u64),
    /// Special file payload containing the merged `rdev` and special file type.
    SpecialFile(SpecialFileEncodingInformation),
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
struct VosFileEntry {
    /// Start offset of the regular file payload in the source object file.
    pub entry_start: u64,
    /// Length of the regular file payload in bytes.
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
/// Virtual object source for a logical tar file stored inside an existing ZFF
/// object.
///
/// `VirtualObjectSourceLogicalTar` reads a tar archive through a [ZffReader],
/// builds an in-memory index of its entries, and then exposes those entries as
/// virtual ZFF files. Regular file payloads are not copied into new chunks.
/// Instead, they are represented by [VirtualFileMap] extents that point back
/// to the byte range of the original tar payload in `source_object_number` /
/// `source_filenumber`.
///
/// Directories, symbolic links, hard links, and special files are represented as
/// virtual footer content. Hashes are calculated over the encoded virtual
/// content, or over the referenced byte range for regular files.
pub struct VirtualObjectSourceLogicalTar<R: ReadAt> {
    /// Indexed tar entries keyed by their generated file number.
    entries: BTreeMap<u64, VosEntry>,
    /// One-based file number of the next entry returned by the iterator.
    index_pointer: u64,
    /// Object number that contains the source tar file.
    source_object_number: u64,
    /// File number of the source tar file inside `source_object_number`.
    source_filenumber: u64,
    /// File numbers of entries that have no parent directory inside the archive.
    root_dir_filenumbers: Vec<u64>,
    /// Reader positioned on the source object and source file.
    zffreader: ZffReader<R>,
    /// Hash algorithms used for generated virtual file footer metadata.
    hash_types: Vec<HashType>,
}

impl<R: ReadAt> VirtualObjectSourceLogicalTar<R> {
    /// Creates a virtual object source from a logical tar file in a ZFF reader.
    ///
    /// `object_number` and `file_number` select the existing logical tar file
    /// that should become the backing store for the virtual object. The tar
    /// archive is scanned once during construction. Each tar entry receives a
    /// generated ZFF file number, metadata is converted into a [`FileHeader`],
    /// and relationship maps for directories, symbolic links, hard links, and
    /// special files are folded into the internal entry list.
    ///
    /// The returned source implements [`Iterator`]. Calling [`Iterator::next`]
    /// yields a [`FileHeader`] together with [`VirtualFileFooterMetadata`] for
    /// one virtual file.
    ///
    /// The [ZffReader] has to be prepared before (objects **must** be 
    /// initialized).
    /// 
    /// # Errors
    ///
    /// Returns an error if the reader cannot select the requested object/file,
    /// the tar archive cannot be read, the archive contains preprocessed tar
    /// records that should have been handled by the `tar` crate, or an entry
    /// cannot be represented as a virtual ZFF file.
    pub fn new(
        mut zffreader: ZffReader<R>, 
        object_number: u64, 
        file_number: Option<u64>, 
        hash_types: Vec<HashType>) -> Result<Self> {
        zffreader.set_active_object(object_number)?;
        if let Some(file_number) = file_number {
            zffreader.set_active_file(file_number)?;
        };
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
            index_pointer: 1,
            source_object_number: object_number,
            source_filenumber: file_number.unwrap_or(0),
            root_dir_filenumbers,
            hash_types,
        })
    }

    fn hash_zffreader_range(&mut self, start: u64, len: u64) -> Result<HashHeader> {
        self.zffreader.seek(SeekFrom::Start(start))?;

        let mut hashers = self.new_hashers();
        let mut remaining = len;
        let mut buffer = [0u8; 64 * 1024];
        while remaining > 0 {
            let bytes_to_read = remaining.min(buffer.len() as u64) as usize;
            self.zffreader.read_exact(&mut buffer[..bytes_to_read])?;
            for (_, hasher) in &mut hashers {
                hasher.update(&buffer[..bytes_to_read]);
            }
            remaining -= bytes_to_read as u64;
        }

        self.finalize_hashers(hashers)
    }

    fn hash_bytes(&self, data: &[u8]) -> Result<HashHeader> {
        let mut hashers = self.new_hashers();
        for (_, hasher) in &mut hashers {
            hasher.update(data);
        }
        self.finalize_hashers(hashers)
    }

    fn new_hashers(&self) -> Vec<(HashType, Box<dyn DynDigest>)> {
        self.hash_types
            .iter()
            .map(|hash_type| (hash_type.clone(), Hash::new_hasher(hash_type)))
            .collect()
    }

    fn finalize_hashers(
        &self,
        hashers: Vec<(HashType, Box<dyn DynDigest>)>,
    ) -> Result<HashHeader> {
        let mut hash_values = Vec::new();
        for (hash_type, hasher) in hashers {
            let hash = hasher.finalize().to_vec();
            hash_values.push(HashValue::new(hash_type, hash, None));
        }

        Ok(HashHeader::new(hash_values))
    }
}

impl<R: ReadAt> VirtualObjectSource for VirtualObjectSourceLogicalTar<R> {
    fn remaining_elements(&self) -> u64 {
        let number_of_entries = self.entries.len() as u64;
        if self.index_pointer > number_of_entries {
            0
        } else {
            number_of_entries - self.index_pointer + 1
        }
    }

    fn root_dir_filenumbers(&self) -> &Vec<u64> {
        &self.root_dir_filenumbers
    }
}

impl<R: ReadAt> Iterator for VirtualObjectSourceLogicalTar<R> {
    type Item = Result<(FileHeader, VirtualFileFooterMetadata)>;

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.index_pointer = n as u64 - 1;
        self.next()
    }

    fn last(self) -> Option<Self::Item>
    where
        Self: Sized,
    {
        let mut voslt = self;
        voslt.index_pointer = voslt.entries.len() as u64 - 1;
        voslt.next()
    }

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.entries.get(&self.index_pointer)?.clone();
        self.index_pointer += 1;
        let file_header = entry.file_header.clone();
        let (hash_header, length, vfc) = match entry.payload {
            VosEntryPayload::File(vos_file_entry) => {
                let hash_header = match self.hash_zffreader_range(
                    vos_file_entry.entry_start,
                    vos_file_entry.entry_len,
                ) {
                    Ok(hash_header) => hash_header,
                    Err(e) => return Some(Err(e)),
                };
                let virtual_file_map = if vos_file_entry.entry_len == 0 {
                    VirtualFileMap::new(file_header.file_number, BTreeMap::new())
                } else {
                    let virtual_file_extent = VirtualFileExtent::new(
                        self.source_object_number,
                        self.source_filenumber,
                        vos_file_entry.entry_start,
                        vos_file_entry.entry_len,
                    );
                    let mut extents = BTreeMap::new();
                    extents.insert(0, virtual_file_extent);
                    VirtualFileMap::new(file_header.file_number, extents)
                };
                (hash_header, vos_file_entry.entry_len, VirtualFileContent::FileMap(virtual_file_map))
            },
            VosEntryPayload::Directory(children) => {
                let hash_header = match self.hash_bytes(&children.encode_directly()) {
                    Ok(hash_header) => hash_header,
                    Err(e) => return Some(Err(e)),
                };
                (hash_header, children.encode_directly().len() as u64, VirtualFileContent::Directory(children))
            },
            VosEntryPayload::Symlink(target) => {
                let target = PlatformString::from(target.as_os_str());
                let encoded_target = target.encode_directly();
                let hash_header = match self.hash_bytes(&encoded_target) {
                    Ok(hash_header) => hash_header,
                    Err(e) => return Some(Err(e)),
                };
                (hash_header, encoded_target.len() as u64, VirtualFileContent::Symlink(target))
            },
            VosEntryPayload::HardLink(target_filenumber) => {
                let encoded_target = target_filenumber.encode_directly();
                let hash_header = match self.hash_bytes(&encoded_target) {
                    Ok(hash_header) => hash_header,
                    Err(e) => return Some(Err(e)),
                };
                (hash_header, encoded_target.len() as u64, VirtualFileContent::Hardlink(target_filenumber))
            },
            VosEntryPayload::SpecialFile(special_file) => {
                let (rdev_id, special_file_type) = match special_file {
                    SpecialFileEncodingInformation::Fifo(rdev_id) => (rdev_id, SpecialFileType::Fifo),
                    SpecialFileEncodingInformation::Char(rdev_id) => (rdev_id, SpecialFileType::Char),
                    SpecialFileEncodingInformation::Block(rdev_id) => (rdev_id, SpecialFileType::Block),
                    SpecialFileEncodingInformation::Socket(rdev_id) => (rdev_id, SpecialFileType::Socket),
                };
                let mut encoded_special_file = rdev_id.encode_directly();
                encoded_special_file.extend_from_slice(&(special_file_type as u8).encode_directly());
                let hash_header = match self.hash_bytes(&encoded_special_file) {
                    Ok(hash_header) => hash_header,
                    Err(e) => return Some(Err(e)),
                };
                (hash_header, encoded_special_file.len() as u64,VirtualFileContent::SpecialFile(rdev_id, special_file_type))
            },
        };
        let virtual_file_footer_metadata = VirtualFileFooterMetadata::new(hash_header, length, vfc);
        Some(Ok((file_header, virtual_file_footer_metadata)))
    }
}
