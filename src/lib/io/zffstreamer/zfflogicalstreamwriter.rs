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
	DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_LOGICAL,
	DEFAULT_CHUNKMAP_SIZE,
	FILE_EXTENSION_INITIALIZER,
	ERROR_MISMATCH_ZFF_VERSION,
	ERROR_MISSING_SEGMENT_MAIN_FOOTER,
	ERROR_INVALID_OPTION_ZFFCREATE,
};
use crate::{
	header::{ObjectHeader, SegmentHeader, ChunkMap, ChunkHeader, DeduplicationChunkMap, FileHeader, EncryptionInformation},
	footer::{MainFooter, SegmentFooter, ObjectFooterLogical},
	FileEncoder,
	ObjectEncoder,

	PhysicalObjectEncoder,
	LogicalObjectEncoder,
	ValueDecoder,
	Segment,
	io::{
		get_file_header, 
		ObjectEncoderInformation,
		zffwriter::{ZffWriterOutput, ZffWriterOptionalParameter, ZffExtenderParameter},
	},
};

#[cfg(target_family = "unix")]
use crate::io::{add_to_hardlink_map};

// - external
use ed25519_dalek::{SigningKey};
use rand::Rng;

/// The [ZffLogicalStreamWriter] can be used to create a new Zff container or extend an existing Zff container with   
/// a logical object - in a very manually way. You can add Files and folders by using a [Reader](std::io::Read) and   
/// define each Fileheader manual. You should use this struct only if you know what you're doing. You can produce a container  
/// which is not readable after creating (e.g. if file numbers mismatch or something similar).
pub struct ZffLogicalStreamWriter {
	object_header: ObjectHeader,
	object_footer: ObjectFooterLogical,
	hash_types: Vec<HashType>,
	output: ZffWriterOutput,
	current_segment_no: u64,
	current_segment_header: SegmentHeader,
	current_segment_footer: SegmentFooter,
	current_chunk_no: u64,
	seek_value: u64,
	current_filename: PathBuf,
	current_chunkmap: ChunkMap,
	main_footer_chunk_map: BTreeMap<u64, u64>,
	object_header_segment_numbers: BTreeMap<u64, u64>, //<object_number, segment_no>
	object_footer_segment_numbers: BTreeMap<u64, u64>, //<object_number, segment_no>
	optional_parameter: ZffWriterOptionalParameter,
	extender_parameter: Option<ZffExtenderParameter>,
}

impl ZffLogicalStreamWriter {
	/// Creates a new [ZffLogicalStreamWriter] instance for the given values.
	pub fn new(
		logical_object_header: ObjectHeader,
		hash_types: Vec<HashType>,
		output: ZffWriterOutput,
		params: ZffWriterOptionalParameter) -> Result<Self> {
		match output {
			ZffWriterOutput::NewContainer(_) => Self::setup_new_container(
												logical_object_header,
												hash_types,
												output,
												params),
			ZffWriterOutput::ExtendContainer(_) => Self::extend_container(
												logical_object_header,
												hash_types,
												output,
												params),
		}
	}

	fn setup_new_container(
		logical_object_header: ObjectHeader,
		hash_types: Vec<HashType>,
		output: ZffWriterOutput,
		params: ZffWriterOptionalParameter) -> Result<Self> {
		Self::setup_container(
			logical_object_header,
			hash_types,
			output,
			1, //initial segment number should always be 1.
			params,
			None)
	}
	fn extend_container(
		logical_object_header: ObjectHeader,
		hash_types: Vec<HashType>,
		output: ZffWriterOutput,
		params: ZffWriterOptionalParameter) -> Result<Self> {
		let files_to_extend = match output {
			ZffWriterOutput::NewContainer(_) => return Err(ZffError::new(ZffErrorKind::InvalidOption, ERROR_INVALID_OPTION_ZFFCREATE)), //TODO,
			ZffWriterOutput::ExtendContainer(ref files_to_extend) => files_to_extend.clone()
		};
		/*
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
		*/
		todo!()
	}

	fn setup_container(
		logical_object_header: ObjectHeader,
		hash_types: Vec<HashType>,
		output: ZffWriterOutput,
		current_segment_no: u64,
		params: ZffWriterOptionalParameter,
		extender_parameter: Option<ZffExtenderParameter>) -> Result<Self> {

		let next_object_number = match &extender_parameter {
			None => 1,
			Some(params) => params.next_object_no,
		};
		let mut logical_object_header = logical_object_header;
		logical_object_header.object_number = next_object_number;

		let initial_chunk_number = match &extender_parameter {
			None => 1,
			Some(params) => params.initial_chunk_number
		};

		let mut object_header_segment_numbers = match &extender_parameter {
			None => BTreeMap::new(),
			Some(params) => params.main_footer.object_header().clone()
		};

		let object_footer_segment_numbers = match &extender_parameter {
			None => BTreeMap::new(),
			Some(params) => params.main_footer.object_footer().clone()
		};

		let object_footer = ObjectFooterLogical::new_empty(
			DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_LOGICAL, 
			logical_object_header.object_number);

		// setup the segment header and segment footer
		let mut seek_value = 0;
		let mut file_extension = String::from(FILE_EXTENSION_INITIALIZER);
		file_extension = file_extension_next_value(&file_extension)?;
    	let mut segment_filename = match &output {
			ZffWriterOutput::NewContainer(path) => path.clone(),
			ZffWriterOutput::ExtendContainer(_) => {
				match &extender_parameter {
					None => unreachable!(),
					Some(params) => params.current_segment.clone()
				}
			}
		};

		// set_extension should not affect the ExtendContainer paths.
    	segment_filename.set_extension(&file_extension);
    	let mut output_file = match &extender_parameter {
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
	    };

	    let (segment_header, mut segment_footer, mut seek_value) = init_segment(&mut output_file, &params, seek_value, 1)?;

	    //TODO: write the segment header and object header and seek to seek value
	    if seek_value == 0 {
	    	seek_value += output_file.write(&segment_header.encode_directly())? as u64;
	    	object_header_segment_numbers.insert(logical_object_header.object_number, current_segment_no);
			segment_footer.add_object_header_offset(logical_object_header.object_number, seek_value);
			seek_value += output_file.write(&logical_object_header.encode_directly())? as u64;
	    };
	    


		Ok(Self {
			object_header: logical_object_header,
			object_footer, //the current object encoder
			hash_types,
			output,
			current_segment_no,
			current_segment_header: segment_header,
			current_segment_footer: segment_footer,
			current_chunk_no: initial_chunk_number,
			seek_value,
			current_filename: segment_filename,
			current_chunkmap: ChunkMap::new_empty(),
			main_footer_chunk_map: BTreeMap::new(),
			object_header_segment_numbers, //<object_number, segment_no>
			object_footer_segment_numbers, //<object_number, segment_no>
			optional_parameter: params,
			extender_parameter,
		})
	}

	/// Same as fn [Self::append_file] but for Vec<u8> as input.
	pub fn append_file_bytes<F, I>(&mut self, fileheader: FileHeader, input_bytes: Vec<u8>) -> Result<()> {
		let cursor = Cursor::new(input_bytes);
		self.append_file(fileheader, cursor)
	}

	/// This method will append a file directly to the container. The file will be written immediatly.
	pub fn append_file<I: std::io::Read + 'static>(
		&mut self, 
		fileheader: FileHeader, 
		input_stream: I) -> Result<()> {
		let enc_info = match EncryptionInformation::try_from(&self.object_header) {
			Ok(enc_info) => Some(enc_info),
			Err(_) => None
		};
		let file_encoder = FileEncoder::new(
			fileheader, 
			self.object_header.clone(),
			Box::new(input_stream), 
			self.hash_types.clone(),
			enc_info,
			self.optional_parameter.signature_key.clone(),
			self.current_chunk_no,
			None, // for symlinks, use the appropiate method
			None, // for hardlinks, use the appropriate method
			Vec::new())?; // for directories, use the appropriate method

		self.encode_file(file_encoder)
	}

	pub fn append_symlink() -> Result<()> {
		todo!()
	}

	pub fn append_directory() -> Result<()> {
		todo!()
	}

	pub fn append_hardlink() -> Result<()> {
		todo!()
	}

	pub fn append_special_device() -> Result<()> {
		todo!()
	}

	fn encode_file(&mut self, mut fileencoder: FileEncoder) -> Result<()> {
		let target_chunk_size = self.object_header.chunk_size as usize;
		let target_segment_size = self.optional_parameter.target_segment_size.unwrap_or(u64::MAX);

		// prepare output
		let mut output = OpenOptions::new().read(true).write(true).append(true).open(&self.current_filename)?;
		output.seek(SeekFrom::Start(self.seek_value))?;

		// use this precalculation instead of calculate the len every round again for performance reasons
		let mut segment_footer_len = self.current_segment_footer.encode_directly().len();
		loop {
			// check if segment size is to small and create a new segment
			// TODO: check also the main_footer size and the object footer size
			if (self.seek_value as usize +
				segment_footer_len +
				target_chunk_size + 
				self.current_chunkmap.current_size()) > target_segment_size as usize {
		        //flush chunkmap
		        if let Some(chunk_no) = self.current_chunkmap.chunkmap.keys().max() {
					self.main_footer_chunk_map.insert(*chunk_no, self.current_segment_no);
					self.current_segment_footer.chunk_map_table.insert(*chunk_no, self.seek_value);
					self.seek_value += output.write(&self.current_chunkmap.encode_directly())? as u64;
					self.current_chunkmap.flush();
				}
		        //finish segment (write segment footer)
		        self.seek_value += output.write(&self.current_segment_footer.encode_directly())? as u64;
		        
		        //create a new segment and sets to output
		        let mut file_extension: String = match self.current_filename.extension() {
		        	Some(ext) => ext.to_string_lossy().to_string(),
		        	None => unreachable!()
		        };
		        file_extension = file_extension_next_value(file_extension)?;
		        self.current_filename.set_extension(file_extension);
		        let mut output = File::create(&self.current_filename)?;

		        //create a new segment footer and segment header and overwrite the old ones
		        self.current_segment_no += 1;
		        (self.current_segment_header, self.current_segment_footer, self.seek_value) = init_segment(&mut output, &self.optional_parameter, 0, self.current_segment_no)?;
		        segment_footer_len = self.current_segment_footer.encode_directly().len();
		        // write the segment header for the new segment.
		        self.seek_value += output.write(&self.current_segment_header.encode_directly())? as u64;
		    };
			let data = match fileencoder.get_next_chunk(self.optional_parameter.deduplication_chunkmap.as_mut()) {
				Ok(data) => data,
				Err(e) => match e.get_kind() {
					ZffErrorKind::ReadEOF => {
						break;	
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
			!self.current_chunkmap.add_chunk_entry(self.current_chunk_no, self.seek_value) {
				if let Some(chunk_no) = self.current_chunkmap.chunkmap.keys().max() {
					self.main_footer_chunk_map.insert(*chunk_no, self.current_segment_no);
					self.current_segment_footer.chunk_map_table.insert(*chunk_no, self.seek_value);
				}
				self.seek_value += output.write(&self.current_chunkmap.encode_directly())? as u64;
				self.current_chunkmap.flush();
				self.current_chunkmap.add_chunk_entry(self.current_chunk_no, self.seek_value);
   			};
   			self.seek_value += output.write(&data)? as u64;
   			self.current_chunk_no += 1;
		}

		Ok(())
	}

	pub fn finish_container(&mut self) -> Result<()> {
		// opens the appropriate file
		let mut output = OpenOptions::new().read(true).write(true).append(true).open(&self.current_filename)?;
		output.seek(SeekFrom::Start(self.seek_value))?;

		// flush the chunkmap 
		if let Some(chunk_no) = self.current_chunkmap.chunkmap.keys().max() {
			self.main_footer_chunk_map.insert(*chunk_no, self.current_segment_no);
			self.current_segment_footer.chunk_map_table.insert(*chunk_no, self.seek_value);
			self.seek_value += output.write(&self.current_chunkmap.encode_directly())? as u64;
			self.current_chunkmap.flush();
		}
		// write the appropriate object footer
		self.object_footer_segment_numbers.insert(self.object_header.object_number, self.current_segment_no);
		self.current_segment_footer.add_object_footer_offset(self.object_header.object_number, self.seek_value);
		//TODO setup object footer
		self.seek_value += output.write(&self.object_footer.encode_directly())? as u64;

		// write the appropriate segment footer
		let main_footer = if let Some(params) = &self.extender_parameter {
			MainFooter::new(
			DEFAULT_FOOTER_VERSION_MAIN_FOOTER, 
			self.current_segment_no, 
			self.object_header_segment_numbers.clone(), 
			self.object_footer_segment_numbers.clone(), 
			self.main_footer_chunk_map.clone(),
			params.main_footer.description_notes().map(|s| s.to_string()), 
			0)
		} else {
			MainFooter::new(
			DEFAULT_FOOTER_VERSION_MAIN_FOOTER, 
			self.current_segment_no, 
			self.object_header_segment_numbers.clone(), 
			self.object_footer_segment_numbers.clone(), 
			self.main_footer_chunk_map.clone(),
			self.optional_parameter.description_notes.clone(), 
			0)
		};

		self.current_segment_footer.set_length_of_segment(self.seek_value + self.current_segment_footer.encode_directly().len() as u64 + main_footer.encode_directly().len() as u64);
		self.seek_value += output.write(&self.current_segment_footer.encode_directly())? as u64;

		output.write_all(&main_footer.encode_directly())?;

		Ok(())
	}
}

impl Drop for ZffLogicalStreamWriter {
	fn drop(&mut self) {
		//TODO use the log module to log errors from drop.
		let _ = self.finish_container();
	}
}

/*
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
		
		// prepare output
		output.seek(SeekFrom::Start(seek_value))?;


		let mut chunkmap = ChunkMap::new_empty();
		chunkmap.set_target_size(chunkmap_size as usize);

		let segment_footer_len = segment_footer.encode_directly().len() as u64;

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
					if let Some(chunk_no) = chunkmap.chunkmap.keys().max() {
						main_footer_chunk_map.insert(*chunk_no, self.current_segment_no);
						segment_footer.chunk_map_table.insert(*chunk_no, written_bytes + seek_value);
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
							// flush the chunkmap 
							if let Some(chunk_no) = chunkmap.chunkmap.keys().max() {
								main_footer_chunk_map.insert(*chunk_no, self.current_segment_no);
								segment_footer.chunk_map_table.insert(*chunk_no, seek_value + written_bytes);
								written_bytes += output.write(&chunkmap.encode_directly())? as u64;
								chunkmap.flush();
							}
							//write the appropriate object footer
							self.object_footer_segment_numbers.insert(self.current_object_encoder.obj_number(), self.current_segment_no);
							segment_footer.add_object_footer_offset(self.current_object_encoder.obj_number(), seek_value + written_bytes);
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
			if ChunkHeader::check_identifier(&mut data_cursor) && 
			!chunkmap.add_chunk_entry(current_chunk_number, seek_value + written_bytes) {
				if let Some(chunk_no) = chunkmap.chunkmap.keys().max() {
					main_footer_chunk_map.insert(*chunk_no, self.current_segment_no);
					segment_footer.chunk_map_table.insert(*chunk_no, seek_value + written_bytes);
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
	    let mut chunk_map = BTreeMap::new();

	    let mut extend = self.extender_parameter.is_some();
	    // TODO: this could be a while loop - a while loop could be more clear here.
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
*/

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

fn sign_key_to_bytes(signature_key: &Option<SigningKey>) -> Option<Vec<u8>> {
	signature_key.as_ref().map(|signing_key| signing_key.to_bytes().to_vec())
}

fn init_segment<O: Read + Seek>(
	output: &mut O,
	optional_parameter: &ZffWriterOptionalParameter,
	seek_value: u64,
	segment_number: u64,
	) -> Result<(SegmentHeader, SegmentFooter, u64)> { //returns the SegmentHeader, SegmentFooter and the new seek_value (e.g. to skip the old SegmentFooter)
	let segment_header = if seek_value == 0 {
		let chunkmap_size = match optional_parameter.chunkmap_size {
			Some(size) => size,
			None => DEFAULT_CHUNKMAP_SIZE,
		};
		let unique_identifier = if optional_parameter.unique_identifier == 0 {
			let mut rng = rand::thread_rng();
			rng.gen()
		} else {
			optional_parameter.unique_identifier
		};
		SegmentHeader::new(unique_identifier, segment_number, chunkmap_size)
	} else {
		output.rewind()?;
		SegmentHeader::decode_directly(output)?
	};
	let segment_footer = if seek_value == 0 {
		SegmentFooter::new_empty(DEFAULT_FOOTER_VERSION_SEGMENT_FOOTER)
	} else {
		//as we shrinked the file before, there should be no main footer present - but a segment footer.
		output.seek(SeekFrom::End(-8))?;
		let footer_offset = u64::decode_directly(output)?;
		output.seek(SeekFrom::Start(footer_offset))?;
		let segment_footer = SegmentFooter::decode_directly(output)?;
		//move the seek position to the footer start, to overwrite the old footer.
		output.seek(SeekFrom::Start(footer_offset))?;
		segment_footer
	};
	let seek_value = if seek_value != 0 {
		output.stream_position()?
	} else {
		seek_value
	};
	Ok((segment_header, segment_footer, seek_value))
}