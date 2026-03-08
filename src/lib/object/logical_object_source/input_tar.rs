// - Parent
use super::*;

/// A [LogicalObjectSource] implementation for reading entries from a TAR archive.
///
/// # Example
/// ```no_run
/// use std::io::Cursor;
/// use tar::{Archive, Builder};
/// use zff::{LogicalObjectSource, LogicalObjectSourceTar};
///
/// // Build a tiny TAR archive in memory.
/// let mut tar_bytes = Vec::new();
/// {
///     let mut builder = Builder::new(&mut tar_bytes);
///     builder.append_data(
///         &mut tar::Header::new_gnu(),
///         "hello.txt",
///         Cursor::new(b"hello world"),
///     )?;
///     builder.finish()?;
/// }
///
/// // Create a TAR-backed logical object source.
/// let archive = Archive::new(Cursor::new(tar_bytes));
/// let source = LogicalObjectSourceTar::try_from(archive)?;
///
/// assert_eq!(source.remaining_elements(), 1);
/// assert_eq!(source.root_dir_filenumbers().len(), 1);
/// # Ok::<(), zff::ZffError>(())
/// ```
pub struct LogicalObjectSourceTar<R: Read + Seek> {
    entries: Vec<(TarEntryReader<R>, FileHeader)>,
    iterator_index: usize,
    root_dir_filenumbers: Vec<u64>,
    symlink_real_paths: HashMap<u64, PathBuf>,
    hardlink_map: HashMap<u64, u64>,
    directory_children: HashMap<u64, Vec<u64>>,
}

impl<R: Read + Seek + 'static> LogicalObjectSource for LogicalObjectSourceTar<R> {
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

impl<R: Read + Seek> TryFrom<Archive<R>> for LogicalObjectSourceTar<R> {
    type Error = ZffError;

    fn try_from(mut archive: Archive<R>) -> Result<Self> {
        // to preserve all metadata stuff
        archive.set_unpack_xattrs(true);
        archive.set_preserve_mtime(true);
        archive.set_preserve_ownerships(true);
        archive.set_preserve_permissions(true);

        let mut temp_tar_entries_metadata = Vec::new();
        let mut tar_entry_reader_vec = Vec::new();
        let mut root_dir_filenumbers = Vec::new();
        let mut directory_children = HashMap::<u64, Vec<u64>>::new(); //<file number of directory, Vec<filenumber of child>>
        let mut current_file_number = 0;
        let mut symlink_real_paths = HashMap::new();
        let mut parent_dir_filenumber_map = HashMap::new();

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
                    let path = entry.path()?;
                    path_to_filenumber_map.insert(path.to_path_buf(), current_file_number);
                },
                _ => () //Symlinks and other hardlinks should not be added.
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

            let size = entry.size();
            let offset = entry.raw_file_position();

            temp_tar_entries_metadata.push((offset, size, fileheader));
        }

        let inner_reader = archive.into_inner();
        let rc = Rc::new(RefCell::new(inner_reader));
        for (offset, size, fileheader) in temp_tar_entries_metadata.drain(..) {
            let inner_rc = Rc::clone(&rc);
            let tar_entry_reader = TarEntryReader::new(inner_rc, offset, size);
            tar_entry_reader_vec.push((tar_entry_reader, fileheader))
        }

        Ok(Self {
            entries: tar_entry_reader_vec,
            iterator_index: 0,
            root_dir_filenumbers,
            symlink_real_paths,
            hardlink_map,
            directory_children: directory_children,
        })
    }
}

fn gen_filetype_encoding_information<R: Read+Seek + 'static>(
	logical_object_source: &LogicalObjectSourceTar<R>) -> Result<FileTypeEncodingInformation> {

	let (entry_reader, current_file_header) = logical_object_source.entries[logical_object_source.iterator_index].clone();
	let current_file_number = current_file_header.file_number;

	match current_file_header.file_type {
		FileType::File => {
			#[cfg_attr(target_os = "windows", allow(clippy::needless_borrows_for_generic_args))]
			Ok(FileTypeEncodingInformation::File(Box::new(entry_reader)))
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
            todo!()
			/*let metadata = match std::fs::metadata(&path) {
				Ok(metadata) => metadata,
				Err(e) => return Err(e.into()),
			};

			let specialfile_info = if metadata.file_type().is_char_device() {
				SpecialFileEncodingInformation::Char(metadata.rdev())
			} else if metadata.file_type().is_block_device() {
				SpecialFileEncodingInformation::Block(metadata.rdev())
			} else if metadata.file_type().is_fifo() {
				SpecialFileEncodingInformation::Fifo(metadata.rdev())
			} else if metadata.file_type().is_socket() {
				SpecialFileEncodingInformation::Socket(metadata.rdev())
			} else {
				return Err(ZffError::new(
					ZffErrorKind::Unsupported,
					ERROR_UNKNOWN_SPECIAL_FILETYPE));
			};
			Ok(FileTypeEncodingInformation::SpecialFile(specialfile_info))*/
		},
	}
}

impl<R: Read+Seek + 'static> Iterator for LogicalObjectSourceTar<R> {
	type Item = (Result<FileTypeEncodingInformation>, FileHeader);

	fn next(&mut self) -> Option<Self::Item> {
		if self.iterator_index == self.entries.len() {
			return None;
		}
        let (_, file_header) = &self.entries[self.iterator_index];
		self.iterator_index += 1;
		let filetype_encoding_information = gen_filetype_encoding_information(&self);
		Some((filetype_encoding_information, file_header.clone()))
	}

	fn count(self) -> usize
		where
			Self: Sized, {
		self.entries.len()
	}

	fn last(self) -> Option<Self::Item>
		where
			Self: Sized, {
		if self.entries.is_empty() {
			return None
		};
		let (_, file_header) = &self.entries[self.entries.len()-1];
		let filetype_encoding_information = gen_filetype_encoding_information(&self);
		Some((filetype_encoding_information, file_header.clone()))
	}
}

/// Contains the inner tar archive entry position and size.
/// A slice from offset to offset + size contains the raw file bytes.
struct TarEntryReader<R: Read + Seek> {
    inner: Rc<RefCell<R>>,
    offset: u64,
    size: u64,
    position: u64,
}

impl<R: Read + Seek> Clone for TarEntryReader<R> {
    fn clone(&self) -> Self {
        TarEntryReader {
            inner: Rc::clone(&self.inner),
            offset: self.offset,
            size: self.size,
            position: self.position,
        }
    }
}

impl<R: Read + Seek> TarEntryReader<R> {
    fn new(inner: Rc<RefCell<R>>, offset: u64, size: u64) -> Self {
        Self {
            inner,
            offset,
            size,
            position: 0,
        }
    }
}

impl<R: Read + Seek> Read for TarEntryReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let remaining = self.size - self.position;
        if remaining == 0 { return Ok(0); }
        let to_read = std::cmp::min(buf.len() as u64, remaining) as usize;
        let mut inner = self.inner.borrow_mut();
        inner.seek(SeekFrom::Start(self.offset + self.position))?;
        let n = inner.read(&mut buf[..to_read])?;
        self.position += n as u64;
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

fn get_file_header_tar<R: Read + Seek, F: Into<String>>(
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

fn get_metadata_ext_tar<R: Read+Seek>(entry: &Entry<R>) -> Result<HashMap<String, MetadataExtendedValue>> {
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
