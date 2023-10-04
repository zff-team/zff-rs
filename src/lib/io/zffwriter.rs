// - STD
use std::collections::BTreeMap;
use std::io::{Read, Write, Seek, SeekFrom, Cursor};
use std::path::{PathBuf};
use std::fs::{File, OpenOptions, remove_file, read_link, read_dir};
use std::collections::{HashMap, VecDeque};
#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;

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
	DEFAULT_CHUNKMAP_SIZE,
	FILE_EXTENSION_INITIALIZER,
	ERROR_MISMATCH_ZFF_VERSION,
	ERROR_MISSING_SEGMENT_MAIN_FOOTER,
	ERROR_INVALID_OPTION_ZFFEXTEND,
	ERROR_INVALID_OPTION_ZFFCREATE,
};
use crate::{
	header::{ObjectHeader, SegmentHeader, ChunkMap, ChunkHeader, DeduplicationChunkMap, FileHeader},
	footer::{MainFooter, SegmentFooter},
	ObjectEncoder,
	PhysicalObjectEncoder,
	LogicalObjectEncoder,
	ValueDecoder,
	Segment,
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
use ed25519_dalek::{SigningKey};

pub enum ZffWriterOutput {
	NewContainer(PathBuf),
	ExtendContainer(Vec<PathBuf>),
}

/// struct contains optional, additional parameter.
#[derive(Default)]
pub struct ZffWriterOptionalParameter {
	pub signature_key: Option<SigningKey>,
	pub target_segment_size: Option<u64>, //if None, the container will not be segmentized.
	pub description_notes: Option<String>,
	pub chunkmap_size: Option<u64>, //default is 32k
	pub deduplication_chunkmap: Option<DeduplicationChunkMap>,
	pub unique_identifier: u64 // TODO: set a random number, if zero?
}

pub struct ZffExtenderParameter {
	pub main_footer: MainFooter,
	pub current_segment: PathBuf,
	pub next_object_no: u64,
	pub initial_chunk_number: u64,
}

impl ZffExtenderParameter {
	pub fn with_data(
		main_footer: MainFooter,
		current_segment: PathBuf,
		next_object_no: u64,
		initial_chunk_number: u64,
		) -> Self {
		Self {
			main_footer,
			current_segment,
			next_object_no,
			initial_chunk_number,
		}
	}
}

/// The ZffWriter can be used to create a new zff container by the given files/values.
pub struct ZffWriter<R: Read> {
	object_encoder: Vec<ObjectEncoderInformation<R>>,
	current_object_encoder: ObjectEncoderInformation<R>, //the current object encoder
	output: ZffWriterOutput,
	current_segment_no: u64,
	object_header_segment_numbers: BTreeMap<u64, u64>, //<object_number, segment_no>
	object_footer_segment_numbers: BTreeMap<u64, u64>, //<object_number, segment_no>
	optional_parameter: ZffWriterOptionalParameter,
	extender_parameter: Option<ZffExtenderParameter>,
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
			ZffWriterOutput::ExtendContainer(_) => Self::extend_container(
												physical_objects,
												logical_objects,
												hash_types,
												output,
												params),
		}
	}

	fn extend_container(
		physical_objects: HashMap<ObjectHeader, R>, // <ObjectHeader, input_data stream>
		logical_objects: HashMap<ObjectHeader, Vec<PathBuf>>, //<ObjectHeader, input_files>
		hash_types: Vec<HashType>,
		output: ZffWriterOutput,
		params: ZffWriterOptionalParameter) -> Result<ZffWriter<R>> {
		let files_to_extend = match output {
			ZffWriterOutput::NewContainer(_) => return Err(ZffError::new(ZffErrorKind::InvalidOption, ERROR_INVALID_OPTION_ZFFCREATE)), //TODO,
			ZffWriterOutput::ExtendContainer(ref files_to_extend) => files_to_extend.clone()
		};
		for ext_file in &files_to_extend {
			let mut raw_segment = File::open(ext_file)?;
			if let Ok(mf) = decode_main_footer(&mut raw_segment) {
				let current_segment = ext_file.to_path_buf();
				
				// checks if the correct header version is set
				let segment = Segment::new_from_reader(&raw_segment)?;
				match segment.header().version() {
					DEFAULT_HEADER_VERSION_SEGMENT_HEADER => (),
					_ => return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_MISMATCH_ZFF_VERSION)),
				}
				let current_segment_no = segment.header().segment_number;
				let initial_chunk_number = match segment.footer().chunk_map_table.keys().max() {
					Some(x) => *x + 1,
					None => return Err(ZffError::new(ZffErrorKind::NoChunksLeft, ""))
				};
				let next_object_no = match mf.object_footer().keys().max() {
					Some(x) => *x + 1,
					None => return Err(ZffError::new(ZffErrorKind::NoObjectsLeft, "")),
				};
				//TODO: Overwrite the old main footer offset with zeros...or the full main footer?
				let extension_parameter = ZffExtenderParameter::with_data(
					mf,
					current_segment,
					next_object_no,
					initial_chunk_number);
				return Self::setup_container(
					physical_objects,
					logical_objects,
					hash_types,
					output,
					current_segment_no,
					params,
					Some(extension_parameter));
			}
			let segment = Segment::new_from_reader(raw_segment)?;
			match segment.header().version() {
				3 => (),
				_ => return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_MISMATCH_ZFF_VERSION)),
			}
		}
		Err(ZffError::new(ZffErrorKind::MissingSegment, ERROR_MISSING_SEGMENT_MAIN_FOOTER))
	}

	fn setup_container(
		physical_objects: HashMap<ObjectHeader, R>, // <ObjectHeader, input_data stream>
		logical_objects: HashMap<ObjectHeader, Vec<PathBuf>>, //<ObjectHeader, input_files>
		hash_types: Vec<HashType>,
		output: ZffWriterOutput,
		current_segment_no: u64,
		params: ZffWriterOptionalParameter,
		extender_parameter: Option<ZffExtenderParameter>) -> Result<ZffWriter<R>> {
		let output_path = match output {
			ZffWriterOutput::NewContainer(path) => path,
			_ => return Err(ZffError::new(ZffErrorKind::InvalidOption, ""))//TODO
		};

		let initial_chunk_number = 1;

		let signature_key_bytes = &params.signature_key.as_ref().map(|signing_key| signing_key.to_bytes().to_vec());
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
			output: ZffWriterOutput::NewContainer(output_path),
			current_segment_no,
			object_header_segment_numbers: BTreeMap::new(), //<object_number, segment_no>
			object_footer_segment_numbers: BTreeMap::new(), //<object_number, segment_no>
			optional_parameter: params,
			extender_parameter,
		})
	}

	fn setup_new_container(
		physical_objects: HashMap<ObjectHeader, R>, // <ObjectHeader, input_data stream>
		logical_objects: HashMap<ObjectHeader, Vec<PathBuf>>, //<ObjectHeader, input_files>
		hash_types: Vec<HashType>,
		output: ZffWriterOutput,
		params: ZffWriterOptionalParameter) -> Result<ZffWriter<R>> {
		Self::setup_container(
			physical_objects, 
			logical_objects,
			hash_types,
			output,
			1, //initial segment number should always be 1.
			params,
			None)
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

				let metadata = match std::fs::symlink_metadata(inner_element.path()) {
					Ok(metadata) => metadata,
					Err(_) => {
						unaccessable_files.push(current_dir.to_string_lossy().to_string());
						continue;
					},
				};
				match File::open(inner_element.path()) {
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

		let mut inner_hardlink_map = HashMap::new();
		let files: Result<Vec<(Box<dyn Read>, FileHeader)>> = files.into_iter()
        .map(|(path, mut file_header)| {
            let file = File::open(path)?;
            let metadata = file.metadata()?;
		    #[cfg(target_family = "unix")]
		    if let Some(inner_map) = hardlink_map.get(&metadata.dev()) {
	    		if let Some(fno) = inner_map.get(&metadata.ino()) {
					if *fno != file_header.file_number {
						file_header.transform_to_hardlink();
						inner_hardlink_map.insert(file_header.file_number, *fno);
					};
		    	}
	     	}
            let file_read: Box<dyn Read> = Box::new(file);
            Ok((file_read, file_header))
        })
        .collect();

		let mut log_obj = LogicalObjectEncoder::new(
			logical_object_header,
			files?,
			root_dir_filenumbers,
			hash_types.to_owned(),
			signature_key_bytes.clone(),
			symlink_real_paths,
			inner_hardlink_map,
			directory_children,
			chunk_number)?;

		for file in unaccessable_files {
			log_obj.add_unaccessable_file(file);
		}
		Ok(log_obj)
	}

	fn write_next_segment<W: Write + Seek>(
		&mut self,
		output: &mut W,
		seek_value: u64, // The seek value is a value of bytes you need to skip (e.g. the main_header, the object_header, ...)
		main_footer_chunk_map: &mut BTreeMap<u64, u64>,
		) -> Result<u64> {

		let mut eof = false; //true, if EOF of input stream is reached.
		output.seek(SeekFrom::Start(seek_value))?;
		let mut written_bytes: u64 = 0;
		let target_chunk_size = self.current_object_encoder.get_obj_header().chunk_size as usize;
		let target_segment_size = self.optional_parameter.target_segment_size.unwrap_or(u64::MAX);
		let chunkmap_size = self.optional_parameter.chunkmap_size.unwrap_or(DEFAULT_CHUNKMAP_SIZE);

		//prepare segment header
		let segment_header = SegmentHeader::new(
			self.optional_parameter.unique_identifier,
			self.current_segment_no,
			chunkmap_size);

		//prepare segment footer
		let mut segment_footer = SegmentFooter::new_empty(DEFAULT_FOOTER_VERSION_SEGMENT_FOOTER);

		//check if the segment size is to small
		if (seek_value as usize +
			segment_header.encode_directly().len() +
			self.current_object_encoder.get_encoded_header().len() +
			segment_footer.encode_directly().len() +
			target_chunk_size) > target_segment_size as usize {
	        
	        return Err(ZffError::new(ZffErrorKind::SegmentSizeToSmall, ""));
	    };

		//write segment header
		written_bytes += output.write(&segment_header.encode_directly())? as u64;	
		
		//write the object header
		if !self.current_object_encoder.written_object_header {
			self.object_header_segment_numbers.insert(self.current_object_encoder.obj_number(), self.current_segment_no);
			segment_footer.add_object_header_offset(self.current_object_encoder.obj_number(), seek_value + written_bytes);
			written_bytes += output.write(&self.current_object_encoder.get_encoded_header())? as u64;
			self.current_object_encoder.written_object_header = true;
		};


		let mut chunkmap = ChunkMap::new_empty();
		chunkmap.set_target_size(chunkmap_size as usize);

		// read chunks and write them into the Writer.
		let segment_footer_len = segment_footer.encode_directly().len() as u64;
		loop {
			if (written_bytes +
				segment_footer_len +
				target_chunk_size as u64 +
				chunkmap.current_size() as u64) > target_segment_size-seek_value {
				
				if written_bytes == segment_header.encode_directly().len() as u64 {
					return Err(ZffError::new(ZffErrorKind::ReadEOF, ""));
				} else {
					//finish segment chunkmap
					if let Some(chunk_no) = chunkmap.chunkmap.keys().max() {
						main_footer_chunk_map.insert(*chunk_no, self.current_segment_no);
						segment_footer.chunk_map_table.insert(*chunk_no, written_bytes);
						written_bytes += output.write(&chunkmap.encode_directly())? as u64;
						chunkmap.flush();
					}
					break;
				}
			};
			let current_offset = seek_value + written_bytes;
			let current_chunk_number = self.current_object_encoder.current_chunk_number();
			let data = match self.current_object_encoder.get_next_data(
				current_offset, 
				self.current_segment_no,
				self.optional_parameter.deduplication_chunkmap.as_mut()) {
				Ok(data) => data,
				Err(e) => match e.get_kind() {
					ZffErrorKind::ReadEOF => {
						if written_bytes == segment_header.encode_directly().len() as u64 {
							return Err(e);
						} else {
							//finish segment chunkmap
							if let Some(chunk_no) = chunkmap.chunkmap.keys().max() {
								main_footer_chunk_map.insert(*chunk_no, self.current_segment_no);
								segment_footer.chunk_map_table.insert(*chunk_no, written_bytes);
								written_bytes += output.write(&chunkmap.encode_directly())? as u64;
								chunkmap.flush();
							}
							//write the appropriate object footer and break the loop
							self.object_footer_segment_numbers.insert(self.current_object_encoder.obj_number(), self.current_segment_no);
							segment_footer.add_object_footer_offset(self.current_object_encoder.obj_number(), seek_value + written_bytes);
							written_bytes += output.write(&self.current_object_encoder.get_encoded_footer()?)? as u64;
							eof = true;
							break;
						}
					},
					ZffErrorKind::InterruptedInputStream => {
						//todo: should be handled in any way...
						break;
					},
					_ => return Err(e),
				},
			};
			let mut data_cursor = Cursor::new(&data);
			if ChunkHeader::check_identifier(&mut data_cursor) && 
			!chunkmap.add_chunk_entry(current_chunk_number, written_bytes) {
				if let Some(chunk_no) = chunkmap.chunkmap.keys().max() {
					main_footer_chunk_map.insert(*chunk_no, self.current_segment_no);
					segment_footer.chunk_map_table.insert(*chunk_no, written_bytes);
				}
				written_bytes += output.write(&chunkmap.encode_directly())? as u64;
				chunkmap.flush();
				chunkmap.add_chunk_entry(current_chunk_number, written_bytes);
   			};
   			written_bytes += output.write(&data)? as u64;
		}

		// finish the segment footer and write the encoded footer into the Writer.
		segment_footer.set_footer_offset(seek_value + written_bytes);
		if eof {
			let main_footer = MainFooter::new(
				DEFAULT_FOOTER_VERSION_MAIN_FOOTER, 
				self.current_segment_no, 
				self.object_header_segment_numbers.clone(), 
				self.object_footer_segment_numbers.clone(), 
				main_footer_chunk_map.clone(),
				self.optional_parameter.description_notes.clone(), 
				0);
			segment_footer.set_length_of_segment(seek_value + written_bytes + segment_footer.encode_directly().len() as u64 + main_footer.encode_directly().len() as u64);
		} else {
			segment_footer.set_length_of_segment(seek_value + written_bytes + segment_footer.encode_directly().len() as u64);
		}
			
		written_bytes += output.write(&segment_footer.encode_directly())? as u64;
		Ok(written_bytes)
	}
	
	/// generates the appropriate .zXX files.
	pub fn generate_files(&mut self) -> Result<()> {
	    let mut file_extension = String::from(FILE_EXTENSION_INITIALIZER);
	    
	    let mut current_offset = 0;
	    let mut seek_value = 0;
	    self.current_segment_no -= 1;
	    let mut chunk_map = BTreeMap::new();

	    loop {
	    	self.current_segment_no += 1;
	    	file_extension = file_extension_next_value(&file_extension)?;
	    	let mut segment_filename = match &self.output {
				ZffWriterOutput::NewContainer(path) => path.clone(),
				ZffWriterOutput::ExtendContainer(_) => return Err(ZffError::new(ZffErrorKind::InvalidOption, ERROR_INVALID_OPTION_ZFFEXTEND))
			};
	    	segment_filename.set_extension(&file_extension);
	    	let mut output_file = File::create(&segment_filename)?;

	    	current_offset = match self.write_next_segment(&mut output_file, seek_value, &mut chunk_map) {
	    		Ok(written_bytes) => {
	    			seek_value = 0;
	    			written_bytes
	    		},
	    		Err(e) => match e.get_kind() {
	    			ZffErrorKind::ReadEOF => {
	    				remove_file(&segment_filename)?;
	    				match self.object_encoder.pop() {
	    					Some(creator_obj_encoder) => self.current_object_encoder = creator_obj_encoder,
	    					None => break,
	    				};
	    				self.current_segment_no -=1;
	    				file_extension = file_extension_previous_value(&file_extension)?;
	    				seek_value = current_offset;
	    				current_offset
	    			},
	    			_ => return Err(e),
	    		},
	    	};
	    }

	    let main_footer = MainFooter::new(
	    	DEFAULT_FOOTER_VERSION_MAIN_FOOTER, 
	    	self.current_segment_no-1, 
	    	self.object_header_segment_numbers.clone(), 
	    	self.object_footer_segment_numbers.clone(),
	    	chunk_map,
	    	self.optional_parameter.description_notes.clone(), 
	    	current_offset);
	    file_extension = file_extension_previous_value(&file_extension)?;
	    let mut segment_filename = match &self.output {
			ZffWriterOutput::NewContainer(path) => path.clone(),
			ZffWriterOutput::ExtendContainer(_) => return Err(ZffError::new(ZffErrorKind::InvalidOption, ERROR_INVALID_OPTION_ZFFEXTEND))
		};
		segment_filename.set_extension(&file_extension);
	    let mut output_file = OpenOptions::new().write(true).append(true).open(&segment_filename)?;
	    output_file.write_all(&main_footer.encode_directly())?;

	    Ok(())
	}
}

fn decode_main_footer<R: Read + Seek>(raw_segment: &mut R) -> Result<MainFooter> {
	raw_segment.seek(SeekFrom::End(-8))?;
	let footer_offset = u64::decode_directly(raw_segment)?;
	raw_segment.seek(SeekFrom::Start(footer_offset))?;
	match MainFooter::decode_directly(raw_segment) {
		Ok(mf) => {
			raw_segment.rewind()?;
			Ok(mf)
		},
		Err(e) => match e.get_kind() {
			ZffErrorKind::HeaderDecodeMismatchIdentifier => {
				raw_segment.rewind()?;
				Err(e)
			},
			_ => Err(e)
		}
	}
}