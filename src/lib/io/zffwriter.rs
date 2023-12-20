// - STD
use std::collections::BTreeMap;
use std::io::{Read, Write, Seek, SeekFrom, Cursor};
use std::path::{PathBuf, Path};
use std::fs::{File, Metadata, OpenOptions, remove_file, read_link, read_dir, metadata};
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
	file_extension_previous_value
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

use crate::constants::*;

use super::{
	get_file_header,
	ObjectEncoderInformation,
};

use super::*;

// - external
use ed25519_dalek::SigningKey;

#[cfg(feature = "log")]
use log::{error, warn, debug, info};

/// Defines the output for a [ZffWriter].
/// This enum determine, that the [ZffWriter] will extend or build a new Zff container.
pub enum ZffWriterOutput {
	/// Build a new container by using the appropriate Path-prefix
	/// (e.g. if "/home/user/zff_container" is given, "/home/user/zff_container.z??" will be used).
	NewContainer(PathBuf),
	/// Determine an extension of the given zff container (path).
	ExtendContainer(Vec<PathBuf>),
}

/// This struct contains optional, additional parameter for the [ZffWriter].
#[derive(Default, Debug)]
pub struct ZffWriterOptionalParameter {
	/// If given, the appropriate data will be signed by the given [SigningKey](crate::ed25519_dalek::SigningKey).
	pub signature_key: Option<SigningKey>,
	/// If None, the container will not be segmentized. Otherwise, [ZffWriter] ensure that no segment will be larger than this size.
	pub target_segment_size: Option<u64>,
	/// An optional description for the container
	/// (note: you can describe every object with custom descriptions by using the [DescriptionHeader](crate::header::DescriptionHeader)).
	pub description_notes: Option<String>,
	/// If set, the chunkmaps will not grow larger than the given size. Otherwise, the default size 32k will be used.
	pub chunkmap_size: Option<u64>, //default is 32k
	/// Optional [DeduplicationChunkMap](crate::header::DeduplicationChunkMap) to ensure a chunk deduplication (and safe some disk space).
	pub deduplication_chunkmap: Option<DeduplicationChunkMap>,
	/// Will be used as a unique identifier, to assign each segment to the appropriate zff container.
	/// If the [ZffWriter] will be extend an existing Zff container, this value will be ignored.
	pub unique_identifier: u64
}

struct ZffExtenderParameter {
	pub main_footer: MainFooter,
	pub current_segment: PathBuf,
	pub next_object_no: u64,
	pub initial_chunk_number: u64,
}

impl ZffExtenderParameter {
	fn with_data(
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

		// checks if the outputfile is creatable or exists.
		check_zffwriter_output(&output)?;

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
			ZffWriterOutput::NewContainer(_) => return Err(ZffError::new(ZffErrorKind::InvalidOption, ERROR_INVALID_OPTION_ZFFCREATE)),
			ZffWriterOutput::ExtendContainer(ref files_to_extend) => files_to_extend.clone()
		};
		let mut params = params;
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
				let unique_identifier = segment.header().unique_identifier;
				params.unique_identifier = unique_identifier;

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

		let mut next_object_number = match &extender_parameter {
			None => 1,
			Some(params) => params.next_object_no,
		};

		let initial_chunk_number = match &extender_parameter {
			None => 1,
			Some(params) => params.initial_chunk_number
		};

		let mut modify_map_phy = HashMap::new();
		// check if all necessary stuff is available in object header and modify them (if needed)
		for (mut header, reader) in physical_objects {
			// check if all EncryptionHeader are contain a decrypted encryption key.
			if let Some(encryption_header) = &header.encryption_header {
				if encryption_header.get_encryption_key_ref().is_none() {
					return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, header.object_number.to_string()))
				};
			}
			// check if this container should be extended - in that case, modify the apropriate object number
			match &extender_parameter {
				None => (), //TODO: check if the object number should be modified here too (in case of new containers).
				Some(_) => {
					header.object_number = next_object_number;
					next_object_number += 1;
				},
			}
			modify_map_phy.insert(header, reader);
		}
		let physical_objects = modify_map_phy;

		let mut modify_map_log = HashMap::new();
		for (mut header, input_files) in logical_objects {
			//check if all EncryptionHeader are contain a decrypted encryption key.
			if let Some(encryption_header) = &header.encryption_header {
				if encryption_header.get_encryption_key_ref().is_none() {
					return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, header.object_number.to_string()))
				};
			}
			// check if this container should be extended - in that case, modify the apropriate object number
			match &extender_parameter {
				None => (), //TODO: check if the object number should be modified here too (in case of new containers).
				Some(_) => {
					header.object_number = next_object_number;
					next_object_number += 1;
				},
			}
			modify_map_log.insert(header, input_files);
		}
		let logical_objects = modify_map_log;

		let signature_key_bytes = &params.signature_key.as_ref().map(|signing_key| signing_key.to_bytes().to_vec());
		let mut object_encoder = Vec::with_capacity(physical_objects.len()+logical_objects.len());
			
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

		let object_header_segment_numbers = match &extender_parameter {
			None => BTreeMap::new(),
			Some(params) => params.main_footer.object_header().clone()
		};

		let object_footer_segment_numbers = match &extender_parameter {
			None => BTreeMap::new(),
			Some(params) => params.main_footer.object_footer().clone()
		};

		Ok(Self {
			object_encoder,
			current_object_encoder, //the current object encoder
			output,
			current_segment_no,
			object_header_segment_numbers, //<object_number, segment_no>
			object_footer_segment_numbers, //<object_number, segment_no>
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
			#[cfg(feature = "log")]
			info!("Collecting files and folders for logical object {} using following paths: {:?}",
				logical_object_header.object_number, input_files);

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
				directories_to_traversal.push_back((path, parent_file_number, current_file_number));
			} else {
				if metadata.file_type().is_symlink() {
					// the error case should not reached, but if, then the target can't be read (and the file is "empty").
					match read_link(&path) {
						Ok(symlink_real) => symlink_real_paths.insert(current_file_number, symlink_real),
						Err(_) => symlink_real_paths.insert(current_file_number, PathBuf::from("")),
					};
				}
				let mut file_header = match get_file_header(&path, current_file_number, parent_file_number) {
					Ok(file_header) => file_header,
					Err(_) => continue,
				};

				//test if file is readable and exists.
				check_file_accessibility(&path, &mut file_header);

				// add the file to the hardlink map
				add_to_hardlink_map(&mut hardlink_map, &metadata, current_file_number);

				files.push((path.clone(), file_header));
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
				#[allow(unused_variables)]
				let inner_element = match inner_element {
					Ok(element) => element,
					Err(e) => {
						// not sure if this can be reached, as we checked a few things before.
						#[cfg(feature = "log")]
						debug!("Error while trying to unwrap the inner element of the element iterator of {}: {e}.", current_dir.display());
						continue;
					}
				};

				let metadata = match check_and_get_metadata(&inner_element.path()) {
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
					check_file_accessibility(&inner_element.path(), &mut file_header);
					
					add_to_hardlink_map(&mut hardlink_map, &metadata, current_file_number);

					files.push((inner_element.path().clone(), file_header));
				}
			}
		}

		#[cfg(target_family = "unix")]
		let hardlink_map = transform_hardlink_map(hardlink_map, &mut files)?;

		#[cfg(target_family = "windows")]
		let hardlink_map = HashMap::new();

		let log_obj = LogicalObjectEncoder::new(
			logical_object_header,
			files,
			root_dir_filenumbers,
			hash_types.to_owned(),
			signature_key_bytes.clone(),
			symlink_real_paths,
			hardlink_map,
			directory_children,
			chunk_number)?;
		Ok(log_obj)
	}

	fn write_next_segment<O: Read + Write + Seek>(
		&mut self,
		output: &mut O,
		seek_value: u64, // The seek value is a value of bytes you need to skip (e.g. the main_header, the object_header, ...)
		main_footer_chunk_map: &mut BTreeMap<u64, u64>,
		extend: bool
		) -> Result<u64> {

		let mut eof = false; //true, if EOF of input stream is reached.
		let mut written_bytes: u64 = 0;
		let target_chunk_size = self.current_object_encoder.get_obj_header().chunk_size as usize;
		let target_segment_size = self.optional_parameter.target_segment_size.unwrap_or(u64::MAX);
		let chunkmap_size = self.optional_parameter.chunkmap_size.unwrap_or(DEFAULT_CHUNKMAP_SIZE);

		// prepare segment header
		// check if this is a new container (and create a new segment header) or an expansion of an existing container
		// (and read the appropriate segment header to calculate size)
		let segment_header = if extend {
				// seek to the start position and read the segment header
				output.seek(SeekFrom::Start(0))?;
				SegmentHeader::decode_directly(output)?
		} else {
			SegmentHeader::new(self.optional_parameter.unique_identifier, self.current_segment_no, chunkmap_size)
		};

		//prepare segment footer
		let mut segment_footer = if extend {
			//as we shrinked the file before, there should be no main footer present - but a segment footer.
			output.seek(SeekFrom::End(-8))?;
			let footer_offset = u64::decode_directly(output)?;
			output.seek(SeekFrom::Start(footer_offset))?;
			let segment_footer = SegmentFooter::decode_directly(output)?;
			//move the seek position to the footer start, to overwrite the old footer.
			output.seek(SeekFrom::Start(footer_offset))?;
			segment_footer

		} else {
			let mut segment_footer = SegmentFooter::new_empty(DEFAULT_FOOTER_VERSION_SEGMENT_FOOTER);
			segment_footer.first_chunk_number = self.current_object_encoder.current_chunk_number();
			segment_footer
		};
		
		// prepare output
		output.seek(SeekFrom::Start(seek_value))?;

		//check if the segment size is to small
		if (seek_value as usize +
			segment_header.encode_directly().len() +
			self.current_object_encoder.get_encoded_header().len() +
			segment_footer.encode_directly().len() +
			target_chunk_size) > target_segment_size as usize {
	        return Err(ZffError::new(ZffErrorKind::SegmentSizeToSmall, ""));
	    };

		//write segment header
		if !extend {
			written_bytes += output.write(&segment_header.encode_directly())? as u64;
		}
		
		//write the object header
		if !self.current_object_encoder.written_object_header {
			let object_number = self.current_object_encoder.obj_number();
			self.object_header_segment_numbers.insert(object_number, self.current_segment_no);
			segment_footer.add_object_header_offset(object_number, seek_value + written_bytes);
			#[cfg(feature = "log")]
			debug!("Writing object {object_number}");
			written_bytes += output.write(&self.current_object_encoder.get_encoded_header())? as u64;
			self.current_object_encoder.written_object_header = true;
		};


		let mut chunkmap = ChunkMap::new_empty();
		chunkmap.set_target_size(chunkmap_size as usize);

		let mut segment_footer_len = segment_footer.encode_directly().len() as u64;

		// read chunks and write them into the Writer.
		loop {
			if (written_bytes +
				segment_footer_len +
				target_chunk_size as u64 +
				chunkmap.current_size() as u64) > target_segment_size-seek_value {
				
				if written_bytes == segment_header.encode_directly().len() as u64 {
					return Err(ZffError::new(ZffErrorKind::ReadEOF, ""));
				} else {
					//finish segment chunkmap
					if let Some(chunk_no) = chunkmap.chunkmap().keys().max() {
						main_footer_chunk_map.insert(*chunk_no, self.current_segment_no);
						segment_footer.chunk_map_table.insert(*chunk_no, written_bytes + seek_value);
						written_bytes += output.write(&chunkmap.encode_directly())? as u64;
						chunkmap.flush();
					}
					break;
				}
			};
			let current_chunk_number = self.current_object_encoder.current_chunk_number();

			// check if the chunkmap is full - this lines are necessary to ensure
			// the correct file footer offset is set while e.g. reading a bunch of empty files.
			if chunkmap.is_full() {
				if let Some(chunk_no) = chunkmap.chunkmap().keys().max() {
					main_footer_chunk_map.insert(*chunk_no, self.current_segment_no);
					segment_footer.chunk_map_table.insert(*chunk_no, seek_value + written_bytes);
					segment_footer_len += 16; //append 16 bytes to segment footer len
				}
				written_bytes += output.write(&chunkmap.encode_directly())? as u64;
				chunkmap.flush();
   			};

   			let current_offset = seek_value + written_bytes;

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
							// flush the chunkmap 
							if let Some(chunk_no) = chunkmap.chunkmap().keys().max() {
								main_footer_chunk_map.insert(*chunk_no, self.current_segment_no);
								segment_footer.chunk_map_table.insert(*chunk_no, seek_value + written_bytes);
								segment_footer_len += 16; //append 16 bytes to segment footer len
								written_bytes += output.write(&chunkmap.encode_directly())? as u64;
								chunkmap.flush();
							}
							//write the appropriate object footer
							self.object_footer_segment_numbers.insert(self.current_object_encoder.obj_number(), self.current_segment_no);
							segment_footer.add_object_footer_offset(self.current_object_encoder.obj_number(), seek_value + written_bytes);
							segment_footer_len += 16; //append 16 bytes to segment footer len
							written_bytes += output.write(&self.current_object_encoder.get_encoded_footer()?)? as u64;
							
							//setup the next object to write down
							match self.object_encoder.pop() {
		    					Some(creator_obj_encoder) => {
		    						self.current_object_encoder = creator_obj_encoder;
		    						continue;
		    					},
		    					None => {
									eof = true;
									break;
			    					},
		    				};	
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
			if ChunkHeader::check_identifier(&mut data_cursor) && // <-- checks if this is a chunk (and not e.g. a file footer or file header)
			!chunkmap.add_chunk_entry(current_chunk_number, seek_value + written_bytes) {
				if let Some(chunk_no) = chunkmap.chunkmap().keys().max() {
					main_footer_chunk_map.insert(*chunk_no, self.current_segment_no);
					segment_footer.chunk_map_table.insert(*chunk_no, seek_value + written_bytes);
					segment_footer_len += 16; //append 16 bytes to segment footer len
				}
				written_bytes += output.write(&chunkmap.encode_directly())? as u64;

				chunkmap.flush();
				chunkmap.add_chunk_entry(current_chunk_number, seek_value + written_bytes);
   			};
   			written_bytes += output.write(&data)? as u64;
		}

		// finish the segment footer and write the encoded footer into the Writer.
		segment_footer.set_footer_offset(seek_value + written_bytes);
		if eof {
			let main_footer = if extend {
				if let Some(params) = &self.extender_parameter {
					MainFooter::new(
					DEFAULT_FOOTER_VERSION_MAIN_FOOTER, 
					self.current_segment_no, 
					self.object_header_segment_numbers.clone(), 
					self.object_footer_segment_numbers.clone(), 
					main_footer_chunk_map.clone(),
					params.main_footer.description_notes().map(|s| s.to_string()), 
					0)
				} else {
					//should never be reached, while the extender_paramter is used many times before.
					unreachable!()
				}
			} else {
				MainFooter::new(
				DEFAULT_FOOTER_VERSION_MAIN_FOOTER, 
				self.current_segment_no, 
				self.object_header_segment_numbers.clone(), 
				self.object_footer_segment_numbers.clone(), 
				main_footer_chunk_map.clone(),
				self.optional_parameter.description_notes.clone(), 
				0)
			};
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
	    //prepare the current segment no for initial looping
	    self.current_segment_no -= 1;
	    let mut chunk_map = BTreeMap::new(); //: check if this main footer chunkmap is filled while you use the extend...

	    let mut extend = self.extender_parameter.is_some();
	    loop {
	    	self.current_segment_no += 1;
	    	file_extension = file_extension_next_value(&file_extension)?;
	    	let mut segment_filename = match &self.output {
				ZffWriterOutput::NewContainer(path) => path.clone(),
				ZffWriterOutput::ExtendContainer(_) => {
					match &self.extender_parameter {
						None => unreachable!(),
						Some(params) => params.current_segment.clone()
					}
				}
			};

			// set_extension should not affect the ExtendContainer paths.
	    	segment_filename.set_extension(&file_extension);
	    	let mut output_file = if extend {
	    		match &self.extender_parameter {
		    		None => File::create(&segment_filename)?,
		    		Some(params) => {
		    			let mut file = OpenOptions::new().append(true).write(true).read(true).open(&params.current_segment)?;
		    			//delete the last main footer
		    			file.seek(SeekFrom::End(-8))?;
		    			let footer_offset = u64::decode_directly(&mut file)?;
						file.seek(SeekFrom::Start(footer_offset))?;
						let new_file_size = file.stream_position()?;
						file.set_len(new_file_size)?;
						seek_value = new_file_size; //sets the new seek value
						file
		    		},
		    	}
	    	} else {
	    		File::create(&segment_filename)?
	    	};
	    	current_offset = match self.write_next_segment(&mut output_file, seek_value, &mut chunk_map, extend) {
	    		Ok(written_bytes) => {
	    			#[cfg(feature = "log")]
					info!("Segment {} was written successfully.", segment_filename.display());
	    			//adds the seek value to the written bytes
	    			extend = false;
	    			current_offset = seek_value + written_bytes;
	    			current_offset
	    		},
	    		Err(e) => match e.get_kind() {
	    			ZffErrorKind::ReadEOF => {
	    				remove_file(&segment_filename)?;
	    				self.current_segment_no -=1;
	    				file_extension = file_extension_previous_value(&file_extension)?;
	    				break;
	    			},
	    			_ => return Err(e),
	    		},
	    	};
	    }
	    let main_footer = if let Some(params) = &self.extender_parameter {
			MainFooter::new(
			DEFAULT_FOOTER_VERSION_MAIN_FOOTER, 
			self.current_segment_no, 
			self.object_header_segment_numbers.clone(), 
			self.object_footer_segment_numbers.clone(), 
			chunk_map,
			params.main_footer.description_notes().map(|s| s.to_string()), 
			current_offset)
		} else {
			MainFooter::new(
			DEFAULT_FOOTER_VERSION_MAIN_FOOTER, 
			self.current_segment_no, 
			self.object_header_segment_numbers.clone(), 
			self.object_footer_segment_numbers.clone(), 
			chunk_map,
			self.optional_parameter.description_notes.clone(), 
			current_offset)
		};
	    let mut segment_filename = match &self.output {
			ZffWriterOutput::NewContainer(path) => path.clone(),
			ZffWriterOutput::ExtendContainer(_) => {
				match &self.extender_parameter {
					None => unreachable!(),
					Some(params) => params.current_segment.clone()
				}
			},
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

#[allow(unused_variables)]
fn check_file_accessibility<P: AsRef<Path>>(path: P, file_header: &mut FileHeader) {
	match File::open(path.as_ref()) {
		Ok(_) => (),
		Err(e) => {
			#[cfg(feature = "log")]
			warn!("The content of the file {} can't be read, due the following error: {e}.\
				The file will be stored as an empty file.", path.display());
			// set the "ua" tag and the full path in file metadata.
			file_header.metadata_ext.insert(METADATA_EXT_KEY_UNACCESSABLE_FILE.to_string(), path.as_ref().to_string_lossy().to_string());
		},
	};
}

fn create_iterator<C: AsRef<Path>>(
	current_dir: C,
	hardlink_map: &mut HashMap<u64, HashMap<u64, u64>>,
	dir_current_file_number: u64,
	dir_parent_file_number: u64,
	directory_children: &mut HashMap::<u64, Vec<u64>>,
	files: &mut Vec<(PathBuf, FileHeader)>,
	) -> Result<std::fs::ReadDir> {
	#[allow(unused_variables)]
	let metadata = match std::fs::symlink_metadata(current_dir.as_ref()) {
		Ok(metadata) => metadata,
		Err(e) => {
			#[cfg(feature = "log")]
			warn!("The metadata of the file {} can't be read. This file will be completly ignored.", &current_dir.display());
			#[cfg(feature = "log")]
			debug!("{e}");
			return Err(e.into());
		},
	};

	if let Some(files_vec) = directory_children.get_mut(&dir_parent_file_number) {
		files_vec.push(dir_current_file_number);
	} else {
		directory_children.insert(dir_parent_file_number, Vec::new());
		directory_children.get_mut(&dir_parent_file_number).unwrap().push(dir_current_file_number);
	};
	let mut file_header = match get_file_header(current_dir.as_ref(), dir_current_file_number, dir_parent_file_number) {
		Ok(file_header) => file_header,
		Err(e) => return Err(e),
	};

	let iterator = match read_dir(current_dir.as_ref()) {
		Ok(iterator) => iterator,
		Err(e) => {
			// if the directory is not readable, we should continue but read the metadata of the directory.
			#[cfg(feature = "log")]
			warn!("The content of the file {} can't be read, due the following error: {e}.\
				The file will be stored as an empty file.", &current_dir.display());
			file_header.metadata_ext.insert(METADATA_EXT_KEY_UNACCESSABLE_FILE.to_string(), current_dir.as_ref().to_string_lossy().to_string());
			return Err(e.into());
		}
	};
	add_to_hardlink_map(hardlink_map, &metadata, dir_current_file_number);
	files.push((current_dir.as_ref().to_path_buf(), file_header));
	
	Ok(iterator)
}

fn check_and_get_metadata<P: AsRef<Path>>(path: P) -> Result<Metadata> {
	match std::fs::symlink_metadata(path.as_ref()) {
		Ok(metadata) => Ok(metadata),
		Err(e) => {
			#[cfg(feature = "log")]
			warn!("The metadata of the file {:?} can't be read. This file will be completly ignored.", inner_element);
			#[cfg(feature = "log")]
			debug!("{e}");
			Err(e.into())
		},
	}
}


#[cfg(target_family = "unix")]
fn transform_hardlink_map(hardlink_map: HashMap<u64, HashMap<u64, u64>>, files: &mut Vec<(PathBuf, FileHeader)>) -> Result<HashMap<u64, u64>> {
	let mut inner_hardlink_map = HashMap::new();
	for (path, file_header) in files {
		let metadata = metadata(&path)?;
		if let Some(inner_map) = hardlink_map.get(&metadata.dev()) {
    		if let Some(fno) = inner_map.get(&metadata.ino()) {
				if *fno != file_header.file_number {
					file_header.transform_to_hardlink();
					inner_hardlink_map.insert(file_header.file_number, *fno);
				};
	    	}
     	}
	}
    Ok(inner_hardlink_map)
}

fn check_zffwriter_output(output: &ZffWriterOutput) -> Result<()> {
	match output {
		ZffWriterOutput::NewContainer(path) => { let mut path = path.clone(); path.set_extension(FIRST_FILE_EXTENSION); return file_exists_or_creatable(&path) },
		ZffWriterOutput::ExtendContainer(path_vec) => {
			for path in path_vec {
				file_exists_or_creatable(path)?;
			}
		},
	}
	Ok(())
}

fn file_exists_or_creatable(path: &PathBuf) -> Result<()> {
    // Check if the file already exists
    if metadata(path).is_ok() {
    	return Ok(())
    }

    // If the file doesn't exist, attempt to create it and check if the operation is successful
    if let Err(e) = File::create(path) {
    	#[cfg(feature = "log")]
    	error!("{ERROR_ZFFWRITER_OPEN_OUTPUTFILE}{}", path.display());
    	return Err(e.into());
    }
    Ok(())
}
