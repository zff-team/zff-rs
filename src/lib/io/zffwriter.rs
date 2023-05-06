// - STD
use std::path::Path;
use std::io::{Read, Write, Seek, SeekFrom, Cursor};
use std::path::{PathBuf};
use std::fs::{File, OpenOptions, remove_file, read_link, read_dir};
use std::collections::{HashMap, VecDeque};


// - internal
use crate::{
	Result,
	HashType,
	HeaderCoding,
	ZffError,
	ZffErrorKind,
	file_extension_next_value,
	file_extension_previous_value,
	DEFAULT_HEADER_VERSION_SEGMENT_HEADER,
	DEFAULT_FOOTER_VERSION_SEGMENT_FOOTER,
	DEFAULT_FOOTER_VERSION_MAIN_FOOTER,
	FILE_EXTENSION_FIRST_VALUE,
};
use crate::{
	header::{ObjectHeader, FileHeader},
	ObjectEncoder,
	PhysicalObjectEncoder,
	LogicalObjectEncoder,
};

use super::{
	get_file_header,
	ObjectEncoderInformation,
};
#[cfg(target_family = "unix")]
use super::{
	add_to_hardlink_map,
};

// - external
use ed25519_dalek::{Keypair};

pub enum ZffWriterOutput {
	NewContainer(PathBuf),
	ExtendContainer(PathBuf),
}

/// struct contains optional, additional parameter.
#[derive(Default)]
pub struct ZffWriterOptionalParameter {
	pub signature_key: Option<Keypair>,
	pub target_segment_size: Option<u64>, //if None, the container will not be segmentized.
	pub description_notes: Option<String>,
	pub deduplicate_chunks: bool,
}



/// The ZffCreator can be used to create a new zff container by the given files/values.
pub struct ZffWriter<R: Read> {
	object_encoder: Vec<ObjectEncoderInformation<R>>,
	current_object_encoder: ObjectEncoderInformation<R>, //the current object encoder
	output_filenpath: PathBuf,
	current_segment_no: u64,
	last_accepted_segment_filepath: PathBuf,
	object_header_segment_numbers: HashMap<u64, u64>, //<object_number, segment_no>
	object_footer_segment_numbers: HashMap<u64, u64>, //<object_number, segment_no>
	optional_parameter: ZffWriterOptionalParameter,
}

impl<R: Read> ZffWriter<R> {
	/// Creates a new [ZffWriter] instance for the given values.
	pub fn new(
		physical_objects: HashMap<ObjectHeader, R>, // <ObjectHeader, input_data stream>
		logical_objects: HashMap<ObjectHeader, Vec<PathBuf>>, //<ObjectHeader, input_files>
		hash_types: Vec<HashType>,
		output: ZffWriterOutput,
		params: ZffWriterOptionalParameter) -> Result<ZffWriter<R>> {
		match output {
			ZffWriterOutput::NewContainer(_) => Self::setup_new_container(
												physical_objects,
												logical_objects,
												hash_types,
												output,
												params),
			_ => unimplemented!()
		}
	}

	fn setup_new_container(
	physical_objects: HashMap<ObjectHeader, R>, // <ObjectHeader, input_data stream>
		logical_objects: HashMap<ObjectHeader, Vec<PathBuf>>, //<ObjectHeader, input_files>
		hash_types: Vec<HashType>,
		output: ZffWriterOutput,
		params: ZffWriterOptionalParameter) -> Result<ZffWriter<R>> {

		let output_path = match output {
			ZffWriterOutput::NewContainer(path) => path,
			_ => return Err(ZffError::new(ZffErrorKind::InvalidOption, ""))//TODO
		};

		let initial_chunk_number = 1;

		let signature_key_bytes = &params.signature_key.as_ref().map(|keypair| keypair.to_bytes().to_vec());
		let mut object_encoder = Vec::with_capacity(physical_objects.len()+logical_objects.len());

		//check if all EncryptionHeader are contain a decrypted encryption key.
		for header in physical_objects.keys() {
			if let Some(encryption_header) = &header.encryption_header {
				if encryption_header.get_encryption_key_ref().is_none() {
					return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, header.object_number.to_string()))
				};
			}
		}
		for header in logical_objects.keys() {
			if let Some(encryption_header) = &header.encryption_header {
				if encryption_header.get_encryption_key_ref().is_none() {
					return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, header.object_number.to_string()))
				};
			}
		}
		
		Self::setup_physical_object_encoder(
			physical_objects,
			&hash_types,
			signature_key_bytes,
			initial_chunk_number,
			&mut object_encoder)?;

		Self::setup_logical_object_encoder(
			logical_objects,
			&hash_types,
			signature_key_bytes,
			initial_chunk_number,
			&mut object_encoder)?;
		
		object_encoder.reverse();
		let current_object_encoder = match object_encoder.pop() {
			Some(creator_obj_encoder) => creator_obj_encoder,
			None => return Err(ZffError::new(ZffErrorKind::NoObjectsLeft, "")),
		};

		Ok(Self {
			object_encoder,
			current_object_encoder, //the current object encoder
			output_filenpath: output_path,
			current_segment_no: 1, //initial segment number should always be 1.
			last_accepted_segment_filepath: PathBuf::new(),
			object_header_segment_numbers: HashMap::new(), //<object_number, segment_no>
			object_footer_segment_numbers: HashMap::new(), //<object_number, segment_no>
			optional_parameter: params,
		})
	}

	fn setup_physical_object_encoder(
		physical_objects: HashMap<ObjectHeader, R>,
		hash_types: &Vec<HashType>,
		signature_key_bytes: &Option<Vec<u8>>,
		chunk_number: u64,
		object_encoder: &mut Vec<ObjectEncoderInformation<R>>) -> Result<()> {
		for (object_header, stream) in physical_objects {
			let encoder = PhysicalObjectEncoder::new(
				object_header,
				stream,
				hash_types.to_owned(),
				signature_key_bytes.clone(),
				chunk_number)?;
			object_encoder.push(ObjectEncoderInformation::with_data(ObjectEncoder::Physical(Box::new(encoder)), false));
		}
		Ok(())
	}

	fn setup_logical_object_encoder(
		logical_objects: HashMap<ObjectHeader, Vec<PathBuf>>,
		hash_types: &Vec<HashType>,
		signature_key_bytes: &Option<Vec<u8>>,
		chunk_number: u64,
		object_encoder: &mut Vec<ObjectEncoderInformation<R>>) -> Result<()> {
		for (logical_object_header, input_files) in logical_objects {
			let lobj = Self::setup_logical_object(
				logical_object_header,
				input_files,
				hash_types,
				signature_key_bytes,
				chunk_number)?;
			object_encoder.push(
				ObjectEncoderInformation::with_data(
					ObjectEncoder::Logical(
						Box::new(lobj)),
						false));
		}
		Ok(())
	}

	fn setup_logical_object(
		logical_object_header: ObjectHeader,
		input_files: Vec<PathBuf>,
		hash_types: &Vec<HashType>,
		signature_key_bytes: &Option<Vec<u8>>,
		chunk_number: u64) -> Result<LogicalObjectEncoder> {
		let mut current_file_number = 0;
		let mut parent_file_number = 0;
		let mut hardlink_map = HashMap::new();
		let mut unaccessable_files = Vec::new();
		let mut directories_to_traversal = VecDeque::new(); // <(path, parent_file_number, current_file_number)>
		let mut files = Vec::new();
		let mut symlink_real_paths = HashMap::new();
		let mut directory_children = HashMap::<u64, Vec<u64>>::new(); //<file number of directory, Vec<filenumber of child>>
		let mut root_dir_filenumbers = Vec::new();

		//files in virtual root folder
		for path in input_files {
			current_file_number += 1;
			let metadata = match std::fs::symlink_metadata(&path) {
				Ok(metadata) => metadata,
				Err(_) => {
					unaccessable_files.push(path.to_string_lossy().to_string());
					continue;
				},
			};
			//test if file is readable and exists.
			match File::open(&path) {
				Ok(_) => (),
				Err(_) => {
					if !metadata.is_symlink() {
						unaccessable_files.push(path.to_string_lossy().to_string());
					};
					continue;
				},
			};
			root_dir_filenumbers.push(current_file_number);
			if metadata.file_type().is_dir() {
				directories_to_traversal.push_back((path, parent_file_number, current_file_number));
			} else {
				if metadata.file_type().is_symlink() {
					// the error case should never reached, we have already checked that the path exists
					// and is a symbolic link.
					match read_link(&path) {
						Ok(symlink_real) => symlink_real_paths.insert(current_file_number, symlink_real),
						Err(_) => symlink_real_paths.insert(current_file_number, PathBuf::from("")),
					};
				}
				let file_header = match get_file_header(&metadata, &path, current_file_number, parent_file_number) {
					Ok(file_header) => file_header,
					Err(_) => continue,
				};

				#[cfg(target_family = "unix")]
				add_to_hardlink_map(&mut hardlink_map, &metadata, current_file_number);

				files.push((path.clone(), file_header));
			}
		}

		// - traverse files in subfolders
		while let Some((current_dir, dir_parent_file_number, dir_current_file_number)) = directories_to_traversal.pop_front() {
				let element_iterator = match read_dir(&current_dir) {
				Ok(iterator) => iterator,
				Err(_) => {
					unaccessable_files.push(current_dir.to_string_lossy().to_string());
					continue;
				}
			};

			let metadata = match std::fs::symlink_metadata(&current_dir) {
				Ok(metadata) => metadata,
				Err(_) => {
					unaccessable_files.push(current_dir.to_string_lossy().to_string());
					continue;
				},
			};
			match File::open(&current_dir) {
				Ok(_) => (),
				Err(_) => {
					unaccessable_files.push(current_dir.to_string_lossy().to_string());
					continue;
				},
			};
			if let Some(files_vec) = directory_children.get_mut(&dir_parent_file_number) {
				files_vec.push(dir_current_file_number);
			} else {
				directory_children.insert(dir_parent_file_number, Vec::new());
				directory_children.get_mut(&dir_parent_file_number).unwrap().push(dir_current_file_number);
			};

			parent_file_number = dir_current_file_number;
			let file_header = match get_file_header(&metadata, &current_dir, dir_current_file_number, dir_parent_file_number) {
				Ok(file_header) => file_header,
				Err(_) => continue,
			};
			#[cfg(target_family = "unix")]
			add_to_hardlink_map(&mut hardlink_map, &metadata, dir_current_file_number);
			
			files.push((current_dir.clone(), file_header));

			// files in current folder
			for inner_element in element_iterator {
				current_file_number += 1;
				let inner_element = match inner_element {
					Ok(element) => element,
					Err(e) => {
						unaccessable_files.push(e.to_string());
						continue;
					}
				};

				let metadata = match std::fs::symlink_metadata(&inner_element.path()) {
					Ok(metadata) => metadata,
					Err(_) => {
						unaccessable_files.push(current_dir.to_string_lossy().to_string());
						continue;
					},
				};
				match File::open(&inner_element.path()) {
					Ok(_) => (),
					Err(_) => {
						unaccessable_files.push(inner_element.path().to_string_lossy().to_string());
						continue;
					},
				};
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
					let file_header = match get_file_header(&metadata, &path, current_file_number, parent_file_number) {
						Ok(file_header) => file_header,
						Err(_) => continue,
					};
					
					#[cfg(target_family = "unix")]
					add_to_hardlink_map(&mut hardlink_map, &metadata, current_file_number);

					files.push((inner_element.path().clone(), file_header));
				}
			}
		}

		let mut log_obj = LogicalObjectEncoder::new(
			logical_object_header,
			files,
			root_dir_filenumbers,
			hash_types.to_owned(),
			signature_key_bytes.clone(),
			symlink_real_paths,
			hardlink_map,
			directory_children,
			chunk_number)?;

		for file in unaccessable_files {
			log_obj.add_unaccessable_file(file);
		}
		Ok(log_obj)
	}
}