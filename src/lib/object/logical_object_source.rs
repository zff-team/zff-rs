// - Parent
use super::*;

// - STD
use std::fs::File;

// - external
#[cfg(feature = "log")]
use log::debug;

/// A [LogicalObjectSource] implementation to handle files from the filesystem.
/// TODO: Example
pub struct LogicalObjectSourceFilesystem {
	files: Vec<(PathBuf, FileHeader)>,
	iterator_index: usize,
	root_dir_filenumbers: Vec<u64>,
	symlink_real_paths: HashMap<u64, PathBuf>,
	hardlink_map: HashMap<u64, u64>,
	directory_children: HashMap<u64, Vec<u64>>,
}

impl LogicalObjectSource for LogicalObjectSourceFilesystem {
	fn remaining_elements(&self) -> u64 {
		(self.files.len() - self.iterator_index) as u64
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

impl<P: AsRef<Path>> TryFrom<Vec<P>> for LogicalObjectSourceFilesystem {
	type Error = ZffError;
	fn try_from(value: Vec<P>) -> Result<Self> {
		Ok(Self::new(value)?)
	}
}

impl LogicalObjectSourceFilesystem {
	/// Creates a new FilesystemSource with the given file information.
	pub fn new<P: AsRef<Path>>(input_files: Vec<P>) -> Result<Self> {
		let mut current_file_number = 0;
		let mut parent_file_number = 0;
		let mut directories_to_traversal = VecDeque::new(); // <(path, parent_file_number, current_file_number)>
		let mut files = Vec::new();
		let mut symlink_real_paths = HashMap::new();
		let mut directory_children = HashMap::<u64, Vec<u64>>::new(); //<file number of directory, Vec<filenumber of child>>
		let mut root_dir_filenumbers = Vec::new();

		let mut hardlink_map = HashMap::new();

		//files in virtual root folder
		for path in input_files {
			current_file_number += 1;

			let metadata = match check_and_get_metadata(&path) {
				Ok(metadata) => metadata,
				Err(_) => continue,
			};

			root_dir_filenumbers.push(current_file_number);
			if metadata.file_type().is_dir() {
				directories_to_traversal.push_back((PathBuf::from(path.as_ref()), parent_file_number, current_file_number));
			} else {
				if metadata.file_type().is_symlink() {
					// the error case should not reached, but if, then the target can't be read (and the file is "empty").
					match read_link(&path) {
						Ok(symlink_real) => symlink_real_paths.insert(current_file_number, symlink_real),
						Err(_) => symlink_real_paths.insert(current_file_number, PathBuf::from("")),
					};
				}
				let mut file_header = match get_file_header(&path.as_ref(), current_file_number, parent_file_number) {
					Ok(file_header) => file_header,
					Err(_) => continue,
				};

				//test if file is readable and exists.
				check_file_accessibility(&path, &mut file_header);

				// add the file to the hardlink map
				add_to_hardlink_map(&mut hardlink_map, &metadata, current_file_number);

				files.push((PathBuf::from(path.as_ref()), file_header));
			}
		}

		// - traverse files in subfolders
		while let Some((current_dir, dir_parent_file_number, dir_current_file_number)) = directories_to_traversal.pop_front() {
			parent_file_number = dir_current_file_number;
			// creates an iterator to iterate over all files in the appropriate directory
			// if the directory can not be read e.g. due a permission error, the metadata
			// of the directory will be stored in the container as an empty directory.
			let element_iterator = match create_iterator(
				current_dir,
				&mut hardlink_map,
				dir_current_file_number,
				dir_parent_file_number,
				&mut directory_children,
				&mut files,
				) {
				Ok(iterator) => iterator,
				Err(_) => continue,
			};

			// handle files in current folder
			for inner_element in element_iterator {
				#[cfg_attr(not(feature = "log"), allow(unused_variables))]
				let inner_element = match inner_element {
					Ok(element) => element,
					Err(e) => {
						// not sure if this can be reached, as we checked a few things before.
						#[cfg(feature = "log")]
						debug!("Error while trying to unwrap the inner element of the element iterator: {e}.");
						continue;
					}
				};

				let metadata = match check_and_get_metadata(inner_element.path()) {
					Ok(metadata) => metadata,
					Err(_) => continue,
				};

				current_file_number += 1;

				if metadata.file_type().is_dir() {
					directories_to_traversal.push_back((inner_element.path(), parent_file_number, current_file_number));
				} else {
					if let Some(files_vec) = directory_children.get_mut(&parent_file_number) {
						files_vec.push(current_file_number);
					} else {
						directory_children.insert(parent_file_number, Vec::new());
						directory_children.get_mut(&parent_file_number).unwrap().push(current_file_number);
					};

					match read_link(inner_element.path()) {
						Ok(symlink_real) => symlink_real_paths.insert(current_file_number, symlink_real),
						Err(_) => symlink_real_paths.insert(current_file_number, PathBuf::from("")),
					};
					let path = inner_element.path().clone();
					let mut file_header = match get_file_header(&path, current_file_number, parent_file_number) {
						Ok(file_header) => file_header,
						Err(_) => continue,
					};

					//test if file is readable and exists.
					check_file_accessibility(inner_element.path(), &mut file_header);
					
					add_to_hardlink_map(&mut hardlink_map, &metadata, current_file_number);

					files.push((inner_element.path().clone(), file_header));
				}
			}
		}

		#[cfg(target_family = "unix")]
		let hardlink_map = transform_hardlink_map(hardlink_map, &mut files)?;

		#[cfg(target_family = "windows")]
		let hardlink_map = HashMap::new();

		let iterator_index = files.len();
		Ok(Self {
			files,
			iterator_index,
			root_dir_filenumbers,
			symlink_real_paths,
			hardlink_map,
			directory_children
		})
	}
}

impl Iterator for LogicalObjectSourceFilesystem {
	type Item = (Result<FileTypeEncodingInformation>, FileHeader);

	fn next(&mut self) -> Option<Self::Item> {
		if self.iterator_index == 0 {
			return None;
		}
		self.iterator_index -= 1;
		let (_, file_header) = &self.files[self.iterator_index];
		let filetype_encoding_information = gen_filetype_encoding_information(&self);
		Some((filetype_encoding_information, file_header.clone()))
	}

	fn count(self) -> usize
		where
			Self: Sized, {
		self.files.len()
	}

	fn last(self) -> Option<Self::Item>
		where
			Self: Sized, {
		if self.files.is_empty() {
			return None
		};
		let (_, file_header) = &self.files[0];
		let filetype_encoding_information = gen_filetype_encoding_information(&self);
		Some((filetype_encoding_information, file_header.clone()))
	}
}


fn gen_filetype_encoding_information(
	filesystem_data: &LogicalObjectSourceFilesystem) -> Result<FileTypeEncodingInformation> {
	let (path, current_file_header) = &filesystem_data.files[filesystem_data.iterator_index];
	let current_file_number = current_file_header.file_number;

	match current_file_header.file_type {
		FileType::File => {
			#[cfg_attr(target_os = "windows", allow(clippy::needless_borrows_for_generic_args))]
			let reader = match File::open(&path) {
				Ok(reader) => Box::new(reader),
				Err(_) => create_empty_reader()
			};
			Ok(FileTypeEncodingInformation::File(Box::new(reader)))
		},
		FileType::Directory => {
			let mut children = Vec::new();
			for child in filesystem_data.directory_children.get(&current_file_number).unwrap_or(&Vec::new()) {
				children.push(*child);
			};
			Ok(FileTypeEncodingInformation::Directory(children))
		},
		FileType::Symlink => {
			let real_path = filesystem_data
										.symlink_real_paths
										.get(&current_file_number)
										.unwrap_or(&PathBuf::new())
										.clone();
			Ok(FileTypeEncodingInformation::Symlink(real_path))
		},
		FileType::Hardlink => {
			let hardlink_filenumber = filesystem_data.hardlink_map.get(&current_file_number).unwrap_or(&0);
			Ok(FileTypeEncodingInformation::Hardlink(*hardlink_filenumber))
		},
		#[cfg(target_family = "windows")]
		FileType::SpecialFile => unreachable!("Special files are not supported on Windows."),
		#[cfg(target_family = "unix")]
		FileType::SpecialFile => {
			let metadata = match std::fs::metadata(&path) {
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
			Ok(FileTypeEncodingInformation::SpecialFile(specialfile_info))
		},
	}
}

fn create_empty_reader() -> Box<dyn Read> {
	let buffer = Vec::<u8>::new();
	let cursor = Cursor::new(buffer);
	Box::new(cursor)
}