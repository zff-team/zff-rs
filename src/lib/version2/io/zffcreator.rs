// - STD
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
	header::{ObjectHeader, MainHeader, SegmentHeader, ChunkHeader},
	footer::{SegmentFooterBTree as SegmentFooter, MainFooter},
	version2::{
		object::{ObjectEncoder, PhysicalObjectEncoder, LogicalObjectEncoder},
	}
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

/// struct which contains the metadata of the appropriate creator (e.g. like encryption key, main header, ...).
pub struct ZffCreatorMetadataParams {
	encryption_key: Option<Vec<u8>>,
	signature_key: Option<Keypair>,
	main_header: MainHeader,
	header_encryption: bool,
	description_notes: Option<String>,
}

impl ZffCreatorMetadataParams {
	/// constructs a struct with the given metadata.
	pub fn with_data(
		encryption_key: Option<Vec<u8>>,
		signature_key: Option<Keypair>,
		main_header: MainHeader,
		header_encryption: bool,
		description_notes: Option<String>) -> ZffCreatorMetadataParams {
		Self {
			encryption_key,
			signature_key,
			main_header,
			header_encryption,
			description_notes,
		}
	}
}

/// The ZffCreator can be used to create a new zff container by the given files/values.
pub struct ZffCreator<R: Read> {
	object_encoder_vec: Vec<ObjectEncoderInformation<R>>,
	object_encoder: ObjectEncoder<R>, //the current object encoder
	written_object_header: bool,
	unaccessable_files: Vec<String>,
	output_filenpath: String,
	current_segment_no: u64,
	last_accepted_segment_filepath: PathBuf,
	description_notes: Option<String>,
	object_header_segment_numbers: HashMap<u64, u64>, //<object_number, segment_no>
	object_footer_segment_numbers: HashMap<u64, u64>, //<object_number, segment_no>
}

impl<R: Read> ZffCreator<R> {
	/// Creates a new [ZffCreator] instance for the given values.
	pub fn new<O: Into<String>>(
		physical_objects: HashMap<ObjectHeader, R>, // <ObjectHeader, input_data stream>
		logical_objects: HashMap<ObjectHeader, Vec<PathBuf>>, //<ObjectHeader, input_files>
		hash_types: Vec<HashType>,
		output_filenpath: O,
		params: ZffCreatorMetadataParams) -> Result<ZffCreator<R>>{

		let initial_chunk_number = 1;
		let signature_key_bytes = params.signature_key.map(|keypair| keypair.to_bytes().to_vec());

		let mut object_encoder_vec = Vec::new();
		for (object_header, input_data) in physical_objects {
			let object_encoder = PhysicalObjectEncoder::new(
				object_header,
				input_data,
				hash_types.clone(),
				params.encryption_key.clone(),
				signature_key_bytes.clone(),
				params.main_header.clone(),
				initial_chunk_number,
				params.header_encryption)?;
			object_encoder_vec.push(ObjectEncoderInformation::with_data(ObjectEncoder::Physical(object_encoder), false, Vec::new()));
		}
		for (object_header, input_files) in logical_objects {
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

			// - files in subfolders
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

			let object_encoder = LogicalObjectEncoder::new(
				object_header,
				files,
				root_dir_filenumbers,
				hash_types.clone(),
				params.encryption_key.clone(),
				signature_key_bytes.clone(),
				params.main_header.clone(),
				symlink_real_paths,
				hardlink_map,
				directory_children,
				initial_chunk_number,
				params.header_encryption)?;
			object_encoder_vec.push(ObjectEncoderInformation::with_data(ObjectEncoder::Logical(Box::new(object_encoder)), false, unaccessable_files));
		}
		object_encoder_vec.reverse();
		let (object_encoder, written_object_header, unaccessable_files) = match object_encoder_vec.pop() {
			Some(creator_obj_encoder) => (creator_obj_encoder.object_encoder, creator_obj_encoder.written_object_header, creator_obj_encoder.unaccessable_files),
			None => return Err(ZffError::new(ZffErrorKind::NoObjectsLeft, "")),
		};

		Ok(Self {
			object_encoder_vec,
			object_encoder,
			written_object_header,
			unaccessable_files,
			output_filenpath: output_filenpath.into(),
			current_segment_no: 1, //initial segment number should always be 1.
			last_accepted_segment_filepath: PathBuf::new(),
			description_notes: params.description_notes,
			object_header_segment_numbers: HashMap::new(),
			object_footer_segment_numbers: HashMap::new(),
		})
	}

	fn write_next_segment<W: Write + Seek>(
	&mut self,
	output: &mut W,
	seek_value: u64, // The seek value is a value of bytes you need to skip (e.g. the main_header, the object_header, ...)
	) -> Result<u64> {
		let mut eof = false; //true, if EOF of input stream is reached.
		output.seek(SeekFrom::Start(seek_value))?;
		let mut written_bytes: u64 = 0;
		let target_chunk_size = self.object_encoder.main_header().chunk_size();
		let target_segment_size = self.object_encoder.main_header().segment_size();
		
		//prepare segment header
		let segment_header = SegmentHeader::new(
			DEFAULT_HEADER_VERSION_SEGMENT_HEADER,
			self.object_encoder.main_header().unique_identifier(),
			self.current_segment_no);

		//check if the segment size is to small
		if (seek_value as usize +
			segment_header.encode_directly().len() +
			self.object_encoder.get_encoded_header().len() +
			target_chunk_size) > self.object_encoder.main_header().segment_size() as usize {
	        
	        return Err(ZffError::new(ZffErrorKind::SegmentSizeToSmall, ""));
	    };

		//write segment header
		written_bytes += output.write(&segment_header.encode_directly())? as u64;

		//prepare segment footer
		let mut segment_footer = SegmentFooter::new_empty(DEFAULT_FOOTER_VERSION_SEGMENT_FOOTER);	
		
		//write the object header
		if !self.written_object_header {
			self.object_header_segment_numbers.insert(self.object_encoder.obj_number(), self.current_segment_no);
			segment_footer.add_object_header_offset(self.object_encoder.obj_number(), seek_value + written_bytes);
			written_bytes += output.write(&self.object_encoder.get_encoded_header())? as u64;
			self.written_object_header = true;
		};

		// read chunks and write them into the Writer.
		let mut segment_footer_len = segment_footer.encode_directly().len() as u64;
		loop {
			if (written_bytes +
				segment_footer_len +
				target_chunk_size as u64) > target_segment_size-seek_value as u64 {
				
				if written_bytes == segment_header.encode_directly().len() as u64 {
					return Err(ZffError::new(ZffErrorKind::ReadEOF, ""));
				} else {
					break;
				}
			};
			let current_offset = seek_value + written_bytes;
			let current_chunk_number = self.object_encoder.current_chunk_number();
			let data = match self.object_encoder.get_next_data(current_offset, self.current_segment_no) {
				Ok(data) => data,
				Err(e) => match e.get_kind() {
					ZffErrorKind::ReadEOF => {
						if written_bytes == segment_header.encode_directly().len() as u64 {
							return Err(e);
						} else {
							//write the appropriate object footer and break the loop
							self.object_footer_segment_numbers.insert(self.object_encoder.obj_number(), self.current_segment_no);
							segment_footer.add_object_footer_offset(self.object_encoder.obj_number(), seek_value + written_bytes);
							written_bytes += output.write(&self.object_encoder.get_encoded_footer())? as u64;
							eof = true;
							break;
						}
					},
					ZffErrorKind::InterruptedInputStream => {
						break;
					},
					_ => return Err(e),
				},
			};
			written_bytes += output.write(&data)? as u64;
			let mut data_cursor = Cursor::new(&data);
			if ChunkHeader::check_identifier(&mut data_cursor) {
				segment_footer.add_chunk_offset(current_chunk_number, current_offset);
				segment_footer_len += 16;
			};
		}

		// finish the segment footer and write the encoded footer into the Writer.
		segment_footer.set_footer_offset(seek_value + written_bytes);
		if eof {
			let main_footer = MainFooter::new(DEFAULT_FOOTER_VERSION_MAIN_FOOTER, self.current_segment_no, self.object_header_segment_numbers.clone(), self.object_footer_segment_numbers.clone(), self.description_notes.clone(), 0);
			segment_footer.set_length_of_segment(seek_value + written_bytes + segment_footer.encode_directly().len() as u64 + main_footer.encode_directly().len() as u64);
		} else {
			segment_footer.set_length_of_segment(seek_value + written_bytes + segment_footer.encode_directly().len() as u64);
		}
			
		written_bytes += output.write(&segment_footer.encode_directly())? as u64;
		Ok(written_bytes)
	}

	/// generates the appropriate .zXX files.
	pub fn generate_files(&mut self) -> Result<()> {
		let mut first_segment_filename = PathBuf::from(&self.output_filenpath);
	    let mut file_extension = String::from(FILE_EXTENSION_FIRST_VALUE);
	    first_segment_filename.set_extension(&file_extension);
	    self.last_accepted_segment_filepath = first_segment_filename.clone();
	    let mut output_file = File::create(&first_segment_filename)?;
		let encoded_main_header = self.object_encoder.main_header().encode_directly();

	    output_file.write_all(&encoded_main_header)?;
	    let mut main_footer_start_offset = self.write_next_segment(&mut output_file, encoded_main_header.len() as u64)? +
	    								   encoded_main_header.len() as u64;

	    let mut seek_value = 0;
	    loop {
	    	self.current_segment_no += 1;
	    	file_extension = file_extension_next_value(&file_extension)?;
	    	let mut segment_filename = PathBuf::from(&self.output_filenpath);
	    	segment_filename.set_extension(&file_extension);
	    	let mut output_file = File::create(&segment_filename)?;
	    	main_footer_start_offset = match self.write_next_segment(&mut output_file, seek_value) {
	    		Ok(written_bytes) => {
	    			seek_value = 0;
	    			written_bytes
	    		},
	    		Err(e) => match e.get_kind() {
	    			ZffErrorKind::ReadEOF => {
	    				remove_file(&segment_filename)?;
	    				let (object_encoder, written_object_header, unaccessable_files) = match self.object_encoder_vec.pop() {
	    					Some(creator_obj_encoder) => (creator_obj_encoder.object_encoder, creator_obj_encoder.written_object_header, creator_obj_encoder.unaccessable_files),
	    					None => break,
	    				};
	    				self.object_encoder = object_encoder;
	    				self.written_object_header = written_object_header;
	    				self.unaccessable_files = unaccessable_files;
	    				self.current_segment_no -=1;
	    				file_extension = file_extension_previous_value(&file_extension)?;
	    				seek_value = main_footer_start_offset;
	    				main_footer_start_offset
	    			},
	    			_ => return Err(e),
	    		},
	    	};
	    	self.last_accepted_segment_filepath = segment_filename.clone();
	    }

	    let main_footer = MainFooter::new(DEFAULT_FOOTER_VERSION_MAIN_FOOTER, self.current_segment_no-1, self.object_header_segment_numbers.clone(), self.object_footer_segment_numbers.clone(), self.description_notes.clone(), main_footer_start_offset);
	    let mut output_file = OpenOptions::new().write(true).append(true).open(&self.last_accepted_segment_filepath)?;
	    output_file.write_all(&main_footer.encode_directly())?;

	    Ok(())
	}

	/// Returns a reference of the unaccessable files.
	pub fn unaccessable_files(&self) -> &Vec<String> {
		&self.unaccessable_files
	}
}