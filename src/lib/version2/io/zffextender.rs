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
	ValueDecoder,
	file_extension_next_value,
	file_extension_previous_value,
	DEFAULT_HEADER_VERSION_SEGMENT_HEADER,
	DEFAULT_FOOTER_VERSION_SEGMENT_FOOTER,
	ERROR_MISSING_SEGMENT_MAIN_FOOTER,
	ERROR_MISMATCH_ZFF_VERSION,
	ERROR_MISSING_SEGMENT_MAIN_HEADER,
};
use crate::{
	Segment,
	header::{ObjectHeader, MainHeader, SegmentHeader, ChunkHeader},
	footer::{SegmentFooter, MainFooter},
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

/// The [ZffExtender] allows you, to extend an existing zff container by additional objects.
pub struct ZffExtender<R: Read> {
	start_segment: PathBuf,
	size_to_overwrite: u64, //number of bytes to overwrite at the last segment
	object_encoder_vec: Vec<ObjectEncoderInformation<R>>,
	object_encoder: ObjectEncoder<R>, //the current object encoder
	written_object_header: bool,
	unaccessable_files: Vec<String>,
	current_segment_no: u64,
	last_accepted_segment_filepath: PathBuf,
	last_segment_footer: SegmentFooter,
	main_footer: MainFooter,
}

impl<R: Read> ZffExtender<R> {
	/// Creates a new [ZffExtender] instance.
	pub fn new(files_to_extend: Vec<PathBuf>,
		physical_objects: HashMap<ObjectHeader, R>, // <ObjectHeader, input_data stream>
		logical_objects: HashMap<ObjectHeader, Vec<PathBuf>>, //<ObjectHeader, input_files>
		hash_types: Vec<HashType>,
		encryption_key: Option<Vec<u8>>,
		signature_key: Option<Keypair>,
		header_encryption: bool) -> Result<ZffExtender<R>>{
		let mut main_footer = None;
		let mut main_header = None;
		let mut last_segment = PathBuf::new();
		let mut current_segment_no = 0;
		let mut initial_chunk_number = 0;
		let mut object_number = 0;
		let mut size_to_overwrite = 0;
		let mut last_segment_footer = SegmentFooter::new_empty(DEFAULT_FOOTER_VERSION_SEGMENT_FOOTER);
		for ext_file in &files_to_extend {
			let mut raw_segment = File::open(ext_file)?;
			if main_footer.is_none() {
				raw_segment.seek(SeekFrom::End(-8))?;
				let footer_offset = u64::decode_directly(&mut raw_segment)?;
				raw_segment.seek(SeekFrom::Start(footer_offset))?;
				match MainFooter::decode_directly(&mut raw_segment) {
					Ok(mf) => {
						main_footer = Some(mf.clone());
						last_segment = ext_file.to_path_buf();
						raw_segment.rewind()?;
						match MainHeader::decode_directly(&mut raw_segment) {
							Ok(mh) => {
								match mh.version() {
									2 => main_header = Some(mh),
									_ => return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_MISMATCH_ZFF_VERSION)),
								}
								
							},
							Err(e) => match e.get_kind() {
								ZffErrorKind::HeaderDecodeMismatchIdentifier => raw_segment.rewind()?,
								_ => return Err(e),
							}
						}
						let segment = Segment::new_from_reader(&raw_segment)?;
						match segment.header().version() {
							2 => (),
							_ => return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_MISMATCH_ZFF_VERSION)),
						}
						current_segment_no = segment.header().segment_number();
						initial_chunk_number = match segment.footer().chunk_offsets().keys().max() {
							Some(x) => *x + 1,
							None => return Err(ZffError::new(ZffErrorKind::NoChunksLeft, ""))
						};
						object_number = match mf.object_header().keys().max() {
							Some(x) => *x + 1,
							None => return Err(ZffError::new(ZffErrorKind::NoObjectsLeft, "")),
						};
						size_to_overwrite += mf.header_size() + segment.footer().header_size();
						let footer = segment.footer();
						last_segment_footer = footer.clone();
						continue;
					},
					Err(e) => match e.get_kind() {
						ZffErrorKind::HeaderDecodeMismatchIdentifier => raw_segment.rewind()?,
						_ => return Err(e)
					}
				}
			}
			match MainHeader::decode_directly(&mut raw_segment) {
				Ok(mh) => {
					match mh.version() {
						2 => main_header = Some(mh),
						_ => return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_MISMATCH_ZFF_VERSION)),
					}
					
				},
				Err(e) => match e.get_kind() {
					ZffErrorKind::HeaderDecodeMismatchIdentifier => raw_segment.rewind()?,
					_ => return Err(e),
				}
			}
			let segment = Segment::new_from_reader(raw_segment)?;
			match segment.header().version() {
				2 => (),
				_ => return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_MISMATCH_ZFF_VERSION)),
			}		
		}

		let main_header = match main_header {
			Some(mh) => mh,
			None => return Err(ZffError::new(ZffErrorKind::MissingSegment, ERROR_MISSING_SEGMENT_MAIN_HEADER))
		};
		let main_footer = match main_footer {
			Some(mf) => mf,
			None => return Err(ZffError::new(ZffErrorKind::MissingSegment, ERROR_MISSING_SEGMENT_MAIN_FOOTER))
		};
			
		let signature_key_bytes = signature_key.map(|keypair| keypair.to_bytes().to_vec());

		let mut object_encoder_vec = Vec::new();
		for (mut object_header, input_data) in physical_objects {
			object_header.set_object_number(object_number);
			object_number += 1;
			let object_encoder = PhysicalObjectEncoder::new(
				object_header,
				input_data,
				hash_types.clone(),
				encryption_key.clone(),
				signature_key_bytes.clone(),
				main_header.clone(),
				initial_chunk_number,
				header_encryption)?;
			object_encoder_vec.push(ObjectEncoderInformation::with_data(ObjectEncoder::Physical(object_encoder), false, Vec::new()));
		}
		for (mut object_header, input_files) in logical_objects {
			object_header.set_object_number(object_number);
			object_number += 1;
			let mut current_file_number = 1;
			let mut parent_file_number = 0;
			let mut hardlink_map = HashMap::new();
			let mut unaccessable_files = Vec::new();
			let mut directories_to_traversal = VecDeque::new();
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
				let mut inner_dir_elements = VecDeque::new();
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
				
				let element_iterator = element_iterator.peekable();
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

					directories_to_traversal.append(&mut inner_dir_elements);
				}
			}

			let object_encoder = LogicalObjectEncoder::new(
				object_header,
				files,
				root_dir_filenumbers,
				hash_types.clone(),
				encryption_key.clone(),
				signature_key_bytes.clone(),
				main_header.clone(),
				symlink_real_paths,
				hardlink_map,
				directory_children,
				initial_chunk_number,
				header_encryption)?;
			object_encoder_vec.push(ObjectEncoderInformation::with_data(ObjectEncoder::Logical(Box::new(object_encoder)), false, unaccessable_files));
		}
		object_encoder_vec.reverse();
		let (object_encoder, written_object_header, unaccessable_files) = match object_encoder_vec.pop() {
			Some(creator_obj_encoder) => (creator_obj_encoder.object_encoder, creator_obj_encoder.written_object_header, creator_obj_encoder.unaccessable_files),
			None => return Err(ZffError::new(ZffErrorKind::NoObjectsLeft, "")),
		};
		Ok(Self {
			start_segment: last_segment,
			size_to_overwrite: size_to_overwrite as u64,
			object_encoder_vec,
			object_encoder,
			written_object_header,
			unaccessable_files,
			current_segment_no,
			last_accepted_segment_filepath: PathBuf::new(),
			main_footer,
			last_segment_footer,
		})
	}

	// extends the (last) segment.
	fn extend_current_segment<W: Write + Seek>(
		&mut self,
		output: &mut W) -> Result<u64> {
		let mut eof = false;
		// Yes, you can alternatively use stream_len(), but stream_len() uses three seek operations: the following code uses only one seek operation.
		let mut written_bytes: u64 = match output.seek(SeekFrom::End(0)) {
			Ok(value) => value - self.size_to_overwrite, // reduce the value of written bytes by the value of bytes you have to overwrite.
			Err(e) => return Err(e.into())
		};

		let target_chunk_size = self.object_encoder.main_header().chunk_size();
		let target_segment_size = self.object_encoder.main_header().segment_size();

		output.seek(SeekFrom::End(-(self.size_to_overwrite as i64)))?;

		//check if the segment size is to small
		if (self.size_to_overwrite as usize +
			self.object_encoder.get_encoded_header().len() +
			target_chunk_size) > self.object_encoder.main_header().segment_size() as usize {
	        
	        return Err(ZffError::new(ZffErrorKind::SegmentSizeToSmall, ""));
	    };

	    //write the object header
		if !self.written_object_header {
			self.main_footer.add_object_header(self.object_encoder.obj_number(), self.current_segment_no);
			self.last_segment_footer.add_object_header_offset(self.object_encoder.obj_number(), written_bytes);
			written_bytes += output.write(&self.object_encoder.get_encoded_header())? as u64;
			self.written_object_header = true;
		};

		// read chunks and write them into the Writer.
		let mut last_segment_footer_len = self.last_segment_footer.encode_directly().len() as u64;
		loop {
			if (written_bytes +
				 last_segment_footer_len +
				target_chunk_size as u64) > target_segment_size as u64 {
				
				if written_bytes == self.size_to_overwrite {
					return Err(ZffError::new(ZffErrorKind::ReadEOF, ""));
				} else {
					break;
				}
			};
			let current_offset = written_bytes;
			let current_chunk_number = self.object_encoder.current_chunk_number();
			let data = match self.object_encoder.get_next_data(current_offset, self.current_segment_no) {
				Ok(data) => data,
				Err(e) => match e.get_kind() {
					ZffErrorKind::ReadEOF => {
						if written_bytes == self.size_to_overwrite {
							return Err(e);
						} else {
							//write the appropriate object footer and break the loop
							self.main_footer.add_object_footer(self.object_encoder.obj_number(), self.current_segment_no);
							self.last_segment_footer.add_object_footer_offset(self.object_encoder.obj_number(), written_bytes);
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
				self.last_segment_footer.add_chunk_offset(current_chunk_number, current_offset);
				last_segment_footer_len += 16;
			};
		}

		// finish the segment footer and write the encoded footer into the Writer.
		self.last_segment_footer.set_footer_offset(written_bytes);
		if eof {
			self.last_segment_footer.set_length_of_segment(written_bytes + self.last_segment_footer.encode_directly().len() as u64 + self.main_footer.encode_directly().len() as u64);
		} else {
			self.last_segment_footer.set_length_of_segment(written_bytes + self.last_segment_footer.encode_directly().len() as u64);
		}
		written_bytes += output.write(&self.last_segment_footer.encode_directly())? as u64;
		Ok(written_bytes)

	}

	fn write_next_segment<W: Write + Seek>(
	&mut self,
	output: &mut W,
	seek_value: u64, // The seek value is a value of bytes you need to skip (e.g. the main_header, the object_header, ...)
	) -> Result<u64> {	
		let mut eof = false;
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
			self.main_footer.add_object_header(self.object_encoder.obj_number(), self.current_segment_no);
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
							self.main_footer.add_object_footer(self.object_encoder.obj_number(), self.current_segment_no);
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
			segment_footer.set_length_of_segment(seek_value + written_bytes + segment_footer.encode_directly().len() as u64 + self.main_footer.encode_directly().len() as u64);
		} else {
			segment_footer.set_length_of_segment(seek_value + written_bytes + segment_footer.encode_directly().len() as u64);
		}

		written_bytes += output.write(&segment_footer.encode_directly())? as u64;
		Ok(written_bytes)
	}

	/// extends the current .zXX files and generate additional .zXX, if needed.
	pub fn extend(&mut self) -> Result<()> {
		let mut segment_filename = PathBuf::from(&self.start_segment);
		self.last_accepted_segment_filepath = segment_filename.clone();
		let mut main_footer_start_offset = self.size_to_overwrite;
		let mut file_extension = match segment_filename.extension() {
			Some(extension) => match extension.to_str() {
				Some(extension) => String::from(extension),
				None => return Err(ZffError::new(ZffErrorKind::FileExtensionParserError, "")),
			},
			None => return Err(ZffError::new(ZffErrorKind::FileExtensionParserError, "")),
		};
		let mut output_file = OpenOptions::new().write(true).open(&segment_filename)?;
		let mut segment_extended = false;
		let mut seek_value = 0;
		loop {
			if !segment_extended {
				main_footer_start_offset = match self.extend_current_segment(&mut output_file) {
					Ok(offset) => offset,
					Err(e) => match  e.get_kind() {
						ZffErrorKind::ReadEOF => 0, //TODO: only remove the main footer?
						_ => return Err(e),
					}
				};
				segment_extended = true;
			}
			self.current_segment_no += 1;
			file_extension = file_extension_next_value(file_extension)?;
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
	    				file_extension = file_extension_previous_value(file_extension)?;
	    				seek_value = main_footer_start_offset;
	    				main_footer_start_offset
	    			},
	    			_ => return Err(e),
	    		},
	    	};
	    	self.last_accepted_segment_filepath = segment_filename.clone();
		}
		self.main_footer.set_number_of_segments(self.current_segment_no-1);
		self.main_footer.set_footer_offset(main_footer_start_offset);
		let mut output_file = OpenOptions::new().write(true).append(true).open(&self.last_accepted_segment_filepath)?;
	    output_file.write_all(&self.main_footer.encode_directly())?;
	    Ok(())
	}

	/// returns the unique identifier of the underlying zff container.
	pub fn unique_segment_identifier(&self) -> i64 {
		self.object_encoder.main_header().unique_identifier()
	}

}