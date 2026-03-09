// - Parent
use super::*;

// - internal
use helper::{result_combine, makedev};

/// A [LogicalObjectSource] implementation for reading entries from a TAR archive.
pub struct LogicalObjectSourceTar {
    entries: VecDeque<(TarEntryReader, FileHeader)>,
    iterator_index: usize,
    root_dir_filenumbers: Vec<u64>,
    symlink_real_paths: HashMap<u64, PathBuf>,
    hardlink_map: HashMap<u64, u64>,
    directory_children: HashMap<u64, Vec<u64>>,
    special_files_rdev_map: HashMap<u64, SpecialFileEncodingInformation>, //filenumber, SpecialFile(merged rdev)
}

impl LogicalObjectSource for LogicalObjectSourceTar {
	fn remaining_elements(&self) -> u64 {
		(self.entries.len() - self.iterator_index) as u64
	}
 
	fn root_dir_filenumbers(&self) -> &Vec<u64> {
		&self.root_dir_filenumbers
	}

	fn directory_children(&self) -> &HashMap<u64, Vec<u64>> {
		&self.directory_children
	}

	fn hardlink_map(&self) -> &HashMap<u64, u64> {
		&self.hardlink_map
	}

	fn symlink_real_paths(&self) -> &HashMap<u64, PathBuf> {
		&self.symlink_real_paths
	}
}

impl TryFrom<&Path> for LogicalObjectSourceTar {
    type Error = ZffError;

    fn try_from(archive_path: &Path) -> Result<Self> {
        //TODO: check if this is an tar archive and return Err if not?
        let file = std::fs::File::open(&archive_path)?;
        let decompressor = phollpers::compression::decompress(file)?;
        let mut archive = Archive::new(decompressor);

        let tar_entry_reader_file = std::fs::File::open(&archive_path)?;
        let decompressor = phollpers::compression::decompress(tar_entry_reader_file)?;
        let tar_stream_state_rc = Rc::new(RefCell::new(TarStreamState::new(decompressor)));

        // to preserve all metadata stuff
        archive.set_unpack_xattrs(true);
        archive.set_preserve_mtime(true);
        archive.set_preserve_ownerships(true);
        archive.set_preserve_permissions(true);

        let mut entries = VecDeque::new();
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

            let entry = entry?;
            
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
                _ => unreachable!()
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
            // given, the value will be just 0.
            if filetype == FileType::SpecialFile {
                let major = entry.header().device_major().ok().flatten().unwrap_or(0);
                let minor = entry.header().device_minor().ok().flatten().unwrap_or(0);
                let rdev = makedev(major, minor);
                let speical_file = match entry.header().entry_type() {
                    EntryType::Char => SpecialFileEncodingInformation::Char(rdev),
                    EntryType::Block => SpecialFileEncodingInformation::Block(rdev),
                    EntryType::Fifo => SpecialFileEncodingInformation::Fifo(rdev),
                    _ => unreachable!(), //should be handled before.
                };
                special_files_rdev_map.insert(current_file_number, speical_file);
            }

            let path = entry.path()?;
            let filename = match path.file_name() {
                Some(filename) => filename.to_str().unwrap().to_string(), //TODO: check if unwrap() needs to be handled.
                None => return Err(ZffError::new(ZffErrorKind::EncodingError, 
                    format!("{ERROR_TAR_ENCODING_ERROR_NO_FILENAME} {:?}", path)))
            };

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
                    None => unreachable!(), //TODO: handle this. This is definitly a broken tar archive.
                };
                let hardlink_filenumber = match path_to_filenumber_map.get(&target) {
                    Some(filenumber) => *filenumber,
                    None => return Err(ZffError::new(ZffErrorKind::EncodingError, 
                        format!("{ERROR_NOT_IN_MAP} {:?}", target)))
                };
                hardlink_map.insert(current_file_number, hardlink_filenumber);
            }
            let fileheader = get_file_header_tar(&entry, filetype, filename, current_file_number, parent_filenumber)?;
            let entry_start_offset = entry.raw_file_position();
            let entry_size = entry.size();
            let entry_reader_rc_clone = Rc::clone(&tar_stream_state_rc);
            let tar_entry_reader = TarEntryReader::new(entry_reader_rc_clone, entry_start_offset, entry_size);

            entries.push_back((tar_entry_reader, fileheader));
        }

        Ok(Self {
            entries,
            iterator_index: 0,
            root_dir_filenumbers,
            symlink_real_paths,
            hardlink_map,
            directory_children: directory_children,
            special_files_rdev_map,
        })
    }
}

impl TryFrom<&PathBuf> for LogicalObjectSourceTar {
    type Error = ZffError;

    fn try_from(archive_path: &PathBuf) -> Result<Self> {
        Self::try_from(archive_path.as_path())
    }
}

impl TryFrom<PathBuf> for LogicalObjectSourceTar {
    type Error = ZffError;

    fn try_from(archive_path: PathBuf) -> Result<Self> {
        Self::try_from(archive_path.as_path())
    }
}

impl Iterator for LogicalObjectSourceTar {
	type Item = Result<(FileTypeEncodingInformation, FileHeader)>;

	fn next(&mut self) -> Option<Self::Item> {
        let (tar_entry_reader, file_header) = self.entries.pop_front()?;
		let filetype_encoding_information = gen_filetype_encoding_information(self, tar_entry_reader, &file_header);
        self.iterator_index += 1;
		Some(result_combine((filetype_encoding_information, file_header)))
	}

	fn count(self) -> usize
		where
			Self: Sized, {
		self.entries.len()
	}
}

fn gen_filetype_encoding_information(logical_object_source: &mut LogicalObjectSourceTar,
    tar_entry_reader: TarEntryReader,
    current_file_header: &FileHeader) -> Result<FileTypeEncodingInformation> {
        let current_file_number = current_file_header.file_number;

        match current_file_header.file_type {
            FileType::File => {
                #[cfg_attr(target_os = "windows", allow(clippy::needless_borrows_for_generic_args))]
                Ok(FileTypeEncodingInformation::File(Box::new(tar_entry_reader)))
            },
            FileType::Directory => {
                let mut children = Vec::new();
                for child in logical_object_source.directory_children.get(&current_file_number).unwrap_or(&Vec::new()) {
                    children.push(*child);
                };
                Ok(FileTypeEncodingInformation::Directory(children))
            },
            FileType::Symlink => {
                let real_path = logical_object_source
                                            .symlink_real_paths
                                            .get(&current_file_number)
                                            .unwrap_or(&PathBuf::new())
                                            .clone();
                Ok(FileTypeEncodingInformation::Symlink(real_path))
            },
            FileType::Hardlink => {
                let hardlink_filenumber = logical_object_source.hardlink_map.get(&current_file_number).unwrap_or(&0);
                Ok(FileTypeEncodingInformation::Hardlink(*hardlink_filenumber))
            },
            #[cfg(target_family = "windows")]
            FileType::SpecialFile => unreachable!("Special files are not supported on Windows."),
            #[cfg(target_family = "unix")]
            FileType::SpecialFile => {
                let specialfile_info = match logical_object_source.special_files_rdev_map.remove(&current_file_number) {
                    Some(info) => info,
                    None => unreachable!(), //should already be handled in construction phase. Should never reached.
                };
                Ok(FileTypeEncodingInformation::SpecialFile(specialfile_info))
            },
        }
    
}

struct TarStreamState {
    reader: Box<dyn Read>,
    absolute_pos: u64,
}

impl TarStreamState {
    fn new<R: Read + 'static>(reader: R) -> Self {
        Self {
            reader: Box::new(reader),
            absolute_pos: 0
        }
    }

    fn skip_to(&mut self, target: u64) -> std::io::Result<()> {
        if target < self.absolute_pos {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "cannot seek backwards in forward tar stream",
            ));
        }
        let mut remaining = target - self.absolute_pos;
        let mut scratch = [0u8; 8192];
        while remaining > 0 {
            let want = remaining.min(scratch.len() as u64) as usize;
            let n = self.reader.read(&mut scratch[..want])?;
            if n == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "unexpected EOF while skipping")); //TODO: move string to constants
            }
            remaining -= n as u64;
            self.absolute_pos += n as u64;
        }
        Ok(())
    }
}

struct TarEntryReader {
    shared: Rc<RefCell<TarStreamState>>,
    start: u64,
    len: u64,
    consumed: u64,
    activated: bool,
}

impl TarEntryReader {
    fn new(shared: Rc<RefCell<TarStreamState>>, start: u64, len: u64) -> Self {
        Self { shared, start, len, consumed: 0, activated: false }
    }
}

impl Read for TarEntryReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.consumed >= self.len || buf.is_empty() {
            return Ok(0);
        }

        let mut st = self.shared.borrow_mut();

        if !self.activated {
            st.skip_to(self.start)?;
            self.activated = true;
        }

        let remaining = (self.len - self.consumed) as usize;
        let want = remaining.min(buf.len());
        let n = st.reader.read(&mut buf[..want])?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "unexpected EOF in tar entry")); //TODO: move string to constants
        }

        self.consumed += n as u64;
        st.absolute_pos += n as u64;
        Ok(n)
    }
}

fn check_root_path<P: AsRef<Path>>(path: P) -> bool {
    let count = if path.as_ref().has_root() {
        2
    } else {
        1
    };
    if path.as_ref().components().count() == count {
        true
    } else {
        false
    }
}

fn get_file_header_tar<R: Read, F: Into<String>>(
    entry: &Entry<R>,
    filetype: FileType,
    filename: F,
    current_file_number: u64, 
    parent_file_number: u64) -> Result<FileHeader> {

    let metadata_ext = get_metadata_ext_tar(entry)?;

    let file_header = FileHeader::new(
                    current_file_number,
                    filetype,
                    filename.into(),
                    parent_file_number,
                    metadata_ext);
    Ok(file_header)
}

fn get_metadata_ext_tar<R: Read>(entry: &Entry<R>) -> Result<HashMap<String, MetadataExtendedValue>> {
    let mut metadata_ext = HashMap::new();
    let header = entry.header();
    if let Ok(mode) = header.mode() {
        metadata_ext.insert(METADATA_EXT_KEY_MODE.into(), mode.into());
    }
    if let Ok(uid) = header.uid() {
        metadata_ext.insert(METADATA_EXT_KEY_UID.into(), uid.into());
    }
    if let Ok(gid) = header.gid() {
        metadata_ext.insert(METADATA_EXT_KEY_GID.into(), gid.into());
    }
    if let Ok(mtime) = header.mtime() {
        metadata_ext.insert(METADATA_MTIME.into(), mtime.into());
    }

    Ok(metadata_ext)
}
