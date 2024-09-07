// - STD
use std::collections::BTreeMap;
use std::io::{Write, Seek, SeekFrom};
use std::fs::{OpenOptions, remove_file, metadata};

// - internal
use crate::{
	Result,
	header::{SegmentHeader, ChunkOffsetMap, ChunkSizeMap, ChunkFlagMap, ChunkCRCMap},
	footer::{SegmentFooter, MainFooter},
	ValueDecoder,
	Segment,
	HeaderCoding,
	file_extension_next_value,
	file_extension_previous_value
};

use crate::constants::*;

use super::*;

#[cfg(feature = "log")]
use log::{error, debug, info};

/// Defines the output for a [ZffWriter].
/// This enum determine, that the [ZffWriter] will extend or build a new Zff container.
pub enum ZffWriterOutput {
	/// Build a new container by using the appropriate Path-prefix
	/// (e.g. if "/home/user/zff_container" is given, "/home/user/zff_container.z??" will be used).
	NewContainer(PathBuf),
	/// Determine an extension of the given zff container (path).
	ExtendContainer(Vec<PathBuf>),
}

/// The ZffWriter can be used to create a new zff container by the given files/values.
pub struct ZffWriter<R: Read> {
	object_encoder: Vec<ObjectEncoderInformation<R>>,
	current_object_encoder: ObjectEncoderInformation<R>, //the current object encoder
	output: ZffWriterOutput,
	current_segment_no: u64,
	object_header_segment_numbers: BTreeMap<u64, u64>, //<object_number, segment_no>
	object_footer_segment_numbers: BTreeMap<u64, u64>, //<object_number, segment_no>
	optional_parameter: ZffCreationParameters,
	extender_parameter: Option<ZffExtenderParameter>,
}

impl<R: Read> ZffWriter<R> {
	/// Creates a new [ZffWriter] instance for the given values.
	pub fn new(
		physical_objects: HashMap<ObjectHeader, R>, // <ObjectHeader, input_data stream>
		logical_objects: HashMap<ObjectHeader, Vec<PathBuf>>, //<ObjectHeader, input_files>
		hash_types: Vec<HashType>,
		output: ZffWriterOutput,
		params: ZffCreationParameters) -> Result<ZffWriter<R>> {

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
		params: ZffCreationParameters) -> Result<ZffWriter<R>> {
		let files_to_extend = match output {
			ZffWriterOutput::NewContainer(_) => return Err(ZffError::new(ZffErrorKind::InvalidOption, ERROR_INVALID_OPTION_ZFFCREATE)),
			ZffWriterOutput::ExtendContainer(ref files_to_extend) => files_to_extend.clone()
		};
		let mut params = params;
		for ext_file in &files_to_extend {
			let mut raw_segment = File::open(ext_file)?;
			if let Ok(mf) = decode_main_footer(&mut raw_segment) {
				let current_segment = ext_file.to_path_buf();
				
				let segment = Segment::new_from_reader(&raw_segment)?;
				let current_segment_no = segment.header().segment_number;
				let initial_chunk_number = match segment.footer().chunk_offset_map_table.keys().max() {
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
			// try to decode the segment header to check if the file is a valid segment.
			let _ = Segment::new_from_reader(raw_segment)?;
		}
		Err(ZffError::new(ZffErrorKind::MissingSegment, ERROR_MISSING_SEGMENT_MAIN_FOOTER))
	}

	fn setup_container(
		mut physical_objects: HashMap<ObjectHeader, R>, // <ObjectHeader, input_data stream>
		mut logical_objects: HashMap<ObjectHeader, Vec<PathBuf>>, //<ObjectHeader, input_files>
		hash_types: Vec<HashType>,
		output: ZffWriterOutput,
		current_segment_no: u64,
		params: ZffCreationParameters,
		extender_parameter: Option<ZffExtenderParameter>) -> Result<ZffWriter<R>> {

		let initial_chunk_number = match &extender_parameter {
			None => INITIAL_CHUNK_NUMBER,
			Some(params) => params.initial_chunk_number
		};

		prepare_object_header(&mut physical_objects, &mut logical_objects, &extender_parameter)?;

		let signature_key_bytes = &params.signature_key.as_ref().map(|signing_key| signing_key.to_bytes().to_vec());
		let mut object_encoder = Vec::with_capacity(physical_objects.len()+logical_objects.len());
			
		setup_physical_object_encoder(
			physical_objects,
			&hash_types,
			signature_key_bytes,
			initial_chunk_number,
			&mut object_encoder)?;

		setup_logical_object_encoder(
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
		params: ZffCreationParameters) -> Result<ZffWriter<R>> {
		Self::setup_container(
			physical_objects, 
			logical_objects,
			hash_types,
			output,
			1, //initial segment number should always be 1.
			params,
			None)
	}

	/// Writes the next segment into the given Writer.  
	/// The seek_value is the value of bytes you need to skip (e.g. in case of an extension).  
	/// The main_footer_chunk_map is a map of all chunk numbers and the appropriate segment number.  
	/// The extend parameter is true, if the container should be extended.  
	/// The return value is the number of written bytes.  
	pub fn write_next_segment<O: Read + Write + Seek>(
		&mut self,
		output: &mut O,
		seek_value: u64, // The seek value is a value of bytes you need to skip (e.g. in case of an extension).
		main_footer_chunk_offset_map: &mut BTreeMap<u64, u64>,
		main_footer_chunk_size_map: &mut BTreeMap<u64, u64>,
		main_footer_chunk_flags_map: &mut BTreeMap<u64, u64>,
		main_footer_chunk_crc_map: &mut BTreeMap<u64, u64>,
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
			let mut segment_footer = SegmentFooter::new_empty();
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


		let mut chunk_offset_map = ChunkOffsetMap::new_empty();
		chunk_offset_map.set_target_size(chunkmap_size as usize);

		let mut chunk_size_map = ChunkSizeMap::new_empty();
		chunk_offset_map.set_target_size(chunkmap_size as usize);

		let mut chunk_flags_map = ChunkFlagMap::new_empty();
		chunk_offset_map.set_target_size(chunkmap_size as usize);

		let mut chunk_crc_map = ChunkCRCMap::new_empty();
		chunk_offset_map.set_target_size(chunkmap_size as usize);

		let mut segment_footer_len = segment_footer.encode_directly().len() as u64;

		// read chunks and write them into the Writer.
		loop {
			if (written_bytes +
				segment_footer_len +
				target_chunk_size as u64 +
				chunk_offset_map.current_size() as u64) +
				chunk_size_map.current_size() as u64 +
				chunk_flags_map.current_size() as u64 +
				chunk_crc_map.current_size() as u64
				> target_segment_size-seek_value {
				
				if written_bytes == segment_header.encode_directly().len() as u64 {
					return Err(ZffError::new(ZffErrorKind::ReadEOF, ""));
				} else {
					//finish segment chunkmaps (chunk offset map, chunk size map, chunk flag map, chunk crc map)
					
					// flush the chunkmaps
					written_bytes += flush_chunkmaps(
						&mut chunk_offset_map,
						&mut chunk_size_map,
						&mut chunk_flags_map,
						&mut chunk_crc_map,
						main_footer_chunk_offset_map,
						main_footer_chunk_size_map,
						main_footer_chunk_flags_map,
						main_footer_chunk_crc_map,
						&mut segment_footer,
						self.current_segment_no,
						seek_value,
						output)?;
				
					break;
				}
			};
			let current_chunk_number = self.current_object_encoder.current_chunk_number();

			// check if the chunkmaps are full - this lines are necessary to ensure
			// the correct file footer offset is set while e.g. reading a bunch of empty files.
			if let Ok(flush_written_bytes) = flush_chunk_offset_map_checked(
				&mut chunk_offset_map,
				main_footer_chunk_offset_map,
				&mut segment_footer,
				self.current_segment_no,
				seek_value + written_bytes,
				output) {
				written_bytes += flush_written_bytes;
				segment_footer_len += 16; //append 16 bytes to segment footer len
			}

			if let Ok(flush_written_bytes) = flush_chunk_size_map_checked(
				&mut chunk_size_map,
				main_footer_chunk_size_map,
				&mut segment_footer,
				self.current_segment_no,
				seek_value + written_bytes,
				output) {
				written_bytes += flush_written_bytes;
				segment_footer_len += 16; //append 16 bytes to segment footer len
			}

			if let Ok(flush_written_bytes) = flush_chunk_flags_map_checked(
				&mut chunk_flags_map,
				main_footer_chunk_flags_map,
				&mut segment_footer,
				self.current_segment_no,
				seek_value + written_bytes,
				output) {
				written_bytes += flush_written_bytes;
				segment_footer_len += 16; //append 16 bytes to segment footer len
			}

			if let Ok(flush_written_bytes) = flush_chunk_crc_map_checked(
				&mut chunk_crc_map,
				main_footer_chunk_crc_map,
				&mut segment_footer,
				self.current_segment_no,
				seek_value + written_bytes,
				output) {
				written_bytes += flush_written_bytes;
				segment_footer_len += 16; //append 16 bytes to segment footer len
			}

   			let current_offset = seek_value + written_bytes;

			let prepared_data = match self.current_object_encoder.get_next_data(
				current_offset, 
				self.current_segment_no,
				self.optional_parameter.deduplication_chunkmap.as_mut()) {
				Ok(data) => data,
				Err(e) => match e.get_kind() {
					ZffErrorKind::ReadEOF => {
						if written_bytes == segment_header.encode_directly().len() as u64 {
							return Err(e);
						} else {
							// flush the chunkmaps 
							written_bytes += flush_chunkmaps(
								&mut chunk_offset_map,
								&mut chunk_size_map,
								&mut chunk_flags_map,
								&mut chunk_crc_map,
								main_footer_chunk_offset_map,
								main_footer_chunk_size_map,
								main_footer_chunk_flags_map,
								main_footer_chunk_crc_map,
								&mut segment_footer,
								self.current_segment_no,
								seek_value,
								output)?;
							segment_footer_len += 64; //append 64 bytes to segment footer len
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
					_ => return Err(e),
				},
			};

			//checks if this is a chunk (and not e.g. a file footer or file header)
			match prepared_data {
				PreparedData::PreparedChunk(prepared_chunk) => {
					// adds entry to the chunk offset map
					if !chunk_offset_map.add_chunk_entry(current_chunk_number, seek_value + written_bytes) {
						//flush the chunk offset map
						written_bytes += flush_chunk_offset_map(
							&mut chunk_offset_map, 
							main_footer_chunk_offset_map, 
							&mut segment_footer, 
							self.current_segment_no, 
							seek_value + written_bytes, 
							output)?;
						chunk_offset_map.add_chunk_entry(current_chunk_number, seek_value + written_bytes);
					};

					// adds entry to the chunk size map
					if !chunk_size_map.add_chunk_entry(current_chunk_number, prepared_chunk.size()) {
						//flush the chunk size map
						written_bytes += flush_chunk_size_map(
							&mut chunk_size_map, 
							main_footer_chunk_size_map, 
							&mut segment_footer, 
							self.current_segment_no, 
							seek_value + written_bytes, 
							output)?;
						chunk_size_map.add_chunk_entry(current_chunk_number, prepared_chunk.size());
					};

					// adds entry to the chunk flags map
					if !chunk_flags_map.add_chunk_entry(current_chunk_number, prepared_chunk.flags().clone()) {
						//flush the chunk flags map
						written_bytes += flush_chunk_flags_map(
							&mut chunk_flags_map, 
							main_footer_chunk_flags_map, 
							&mut segment_footer, 
							self.current_segment_no, 
							seek_value + written_bytes, 
							output)?;
						chunk_flags_map.add_chunk_entry(current_chunk_number, prepared_chunk.flags().clone());
					};

					// adds entry to the chunk crc map
					if !chunk_crc_map.add_chunk_entry(current_chunk_number, prepared_chunk.crc().clone()) {
						//flush the chunk crc map
						written_bytes += flush_chunk_crc_map(
							&mut chunk_crc_map, 
							main_footer_chunk_crc_map, 
							&mut segment_footer, 
							self.current_segment_no, 
							seek_value + written_bytes, 
							output)?;
						chunk_crc_map.add_chunk_entry(current_chunk_number, prepared_chunk.crc().clone());
					};

					// writes the prepared chunk into the Writer
					written_bytes += output.write(&prepared_chunk.data())? as u64;
				},
				PreparedData::PreparedFileFooter(data) => written_bytes += output.write(&data)? as u64,
				PreparedData::PreparedFileHeader(data) => written_bytes += output.write(&data)? as u64,
			};
		}

		// finish the segment footer and write the encoded footer into the Writer.
		segment_footer.set_footer_offset(seek_value + written_bytes);
		if eof {
			let main_footer = if extend {
				if let Some(params) = &self.extender_parameter {
					MainFooter::new(
					self.current_segment_no, 
					self.object_header_segment_numbers.clone(), 
					self.object_footer_segment_numbers.clone(), 
					main_footer_chunk_offset_map.clone(),
					main_footer_chunk_size_map.clone(),
					main_footer_chunk_flags_map.clone(),
					main_footer_chunk_crc_map.clone(),
					params.main_footer.description_notes().map(|s| s.to_string()), 
					0)
				} else {
					//should never be reached, while the extender_paramter is used many times before.
					unreachable!()
				}
			} else {
				MainFooter::new(
				self.current_segment_no, 
				self.object_header_segment_numbers.clone(), 
				self.object_footer_segment_numbers.clone(), 
				main_footer_chunk_offset_map.clone(),
				main_footer_chunk_size_map.clone(),
				main_footer_chunk_flags_map.clone(),
				main_footer_chunk_crc_map.clone(),
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
	    
		let mut main_footer_chunk_offset_map = BTreeMap::new(); //TODO: check if this main footer chunkmap is filled while you use the extend...
		let mut main_footer_chunk_size_map = BTreeMap::new();
		let mut main_footer_chunk_flags_map = BTreeMap::new();
		let mut main_footer_chunk_crc_map = BTreeMap::new();


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
		    			let mut file = OpenOptions::new().append(true).read(true).open(&params.current_segment)?;
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
	    	current_offset = match self.write_next_segment(
				&mut output_file, 
				seek_value, 
				&mut main_footer_chunk_offset_map,
				&mut main_footer_chunk_size_map,
				&mut main_footer_chunk_flags_map,
				&mut main_footer_chunk_crc_map, 
				extend) {
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
			self.current_segment_no, 
			self.object_header_segment_numbers.clone(), 
			self.object_footer_segment_numbers.clone(), 
			main_footer_chunk_offset_map,
			main_footer_chunk_size_map,
			main_footer_chunk_flags_map,
			main_footer_chunk_crc_map,
			params.main_footer.description_notes().map(|s| s.to_string()), 
			current_offset)
		} else {
			MainFooter::new(
			self.current_segment_no, 
			self.object_header_segment_numbers.clone(), 
			self.object_footer_segment_numbers.clone(), 
			main_footer_chunk_offset_map,
			main_footer_chunk_size_map,
			main_footer_chunk_flags_map,
			main_footer_chunk_crc_map,
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
	    let mut output_file = OpenOptions::new().append(true).open(&segment_filename)?;
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

// flush the chunkmaps and writes them into the output - but check if the chunkmaps are full.
fn flush_chunkmaps_checked<W: Write>(
	chunk_offset_map: &mut ChunkOffsetMap,
	chunk_size_map: &mut ChunkSizeMap,
	chunk_flags_map: &mut ChunkFlagMap,
	chunk_crc_map: &mut ChunkCRCMap,
	main_footer_chunk_offset_map: &mut BTreeMap<u64, u64>,
	main_footer_chunk_size_map: &mut BTreeMap<u64, u64>,
	main_footer_chunk_flags_map: &mut BTreeMap<u64, u64>,
	main_footer_chunk_crc_map: &mut BTreeMap<u64, u64>,
	segment_footer: &mut SegmentFooter,
	current_segment_no: u64,
	seek_value: u64,
	output: &mut W,
) -> Result<u64> {
	let mut written_bytes = 0;
	// flush the chunk offset map
	if chunk_offset_map.is_full() {
		written_bytes += flush_chunk_offset_map(
			chunk_offset_map, 
			main_footer_chunk_offset_map, 
			segment_footer, 
			current_segment_no, 
			seek_value, 
			output)?;
	}

	// flush the chunk size map
	if chunk_size_map.is_full() {
		written_bytes += flush_chunk_size_map(
			chunk_size_map, 
			main_footer_chunk_size_map, 
			segment_footer, 
			current_segment_no, 
			seek_value, 
			output)?;
	}

	// flush the chunk size map
	if chunk_flags_map.is_full() {
		written_bytes += flush_chunk_flags_map(
			chunk_flags_map, 
			main_footer_chunk_flags_map, 
			segment_footer, 
			current_segment_no, 
			seek_value, 
			output)?;
	}

	// flush the chunk crc map
	if chunk_crc_map.is_full() {
		written_bytes += flush_chunk_crc_map(
			chunk_crc_map, 
			main_footer_chunk_crc_map, 
			segment_footer, 
			current_segment_no, 
			seek_value, 
			output)?;
	}

	Ok(written_bytes)
}

// flushs the chunkmaps and writes them into the output.
fn flush_chunkmaps<W: Write>(
	chunk_offset_map: &mut ChunkOffsetMap,
	chunk_size_map: &mut ChunkSizeMap,
	chunk_flags_map: &mut ChunkFlagMap,
	chunk_crc_map: &mut ChunkCRCMap,
	main_footer_chunk_offset_map: &mut BTreeMap<u64, u64>,
	main_footer_chunk_size_map: &mut BTreeMap<u64, u64>,
	main_footer_chunk_flags_map: &mut BTreeMap<u64, u64>,
	main_footer_chunk_crc_map: &mut BTreeMap<u64, u64>,
	segment_footer: &mut SegmentFooter,
	current_segment_no: u64,
	seek_value: u64,
	output: &mut W,
) -> Result<u64> { // returns the written bytes
	let mut written_bytes = 0;
	// flush the chunk offset map
	written_bytes += flush_chunk_offset_map(
		chunk_offset_map, 
		main_footer_chunk_offset_map, 
		segment_footer, 
		current_segment_no, 
		seek_value, 
		output)?;

	// flush the chunk size map
	written_bytes += flush_chunk_size_map(
		chunk_size_map, 
		main_footer_chunk_size_map, 
		segment_footer, 
		current_segment_no, 
		seek_value, 
		output)?;

	// flush the chunk size map
	written_bytes += flush_chunk_flags_map(
		chunk_flags_map, 
		main_footer_chunk_flags_map, 
		segment_footer, 
		current_segment_no, 
		seek_value, 
		output)?;

	// flush the chunk crc map
	written_bytes += flush_chunk_crc_map(
		chunk_crc_map, 
		main_footer_chunk_crc_map, 
		segment_footer, 
		current_segment_no, 
		seek_value, 
		output)?;

	Ok(written_bytes)
}

fn flush_chunk_offset_map<W: Write>(
	chunk_offset_map: &mut ChunkOffsetMap,
	main_footer_chunk_offset_map: &mut BTreeMap<u64, u64>,
	segment_footer: &mut SegmentFooter,
	current_segment_no: u64,
	seek_value: u64,
	output: &mut W,
) -> Result<u64> {
	let mut written_bytes = 0;
	if let Some(chunk_no) = chunk_offset_map.chunkmap().keys().max() {
		main_footer_chunk_offset_map.insert(*chunk_no, current_segment_no);
		segment_footer.chunk_offset_map_table.insert(*chunk_no, written_bytes + seek_value);
		written_bytes += output.write(&chunk_offset_map.encode_directly())? as u64;
		chunk_offset_map.flush();
	}
	Ok(written_bytes)
}

fn flush_chunk_offset_map_checked<W: Write>(
	chunk_offset_map: &mut ChunkOffsetMap,
	main_footer_chunk_offset_map: &mut BTreeMap<u64, u64>,
	segment_footer: &mut SegmentFooter,
	current_segment_no: u64,
	seek_value: u64,
	output: &mut W,
) -> Result<u64> {
	let mut written_bytes = 0;
	if chunk_offset_map.is_full() {
		written_bytes += flush_chunk_offset_map(
			chunk_offset_map, 
			main_footer_chunk_offset_map, 
			segment_footer, 
			current_segment_no, 
			seek_value, 
			output)?;
	}
	Ok(written_bytes)
}

fn flush_chunk_size_map<W: Write>(
	chunk_size_map: &mut ChunkSizeMap,
	main_footer_chunk_size_map: &mut BTreeMap<u64, u64>,
	segment_footer: &mut SegmentFooter,
	current_segment_no: u64,
	seek_value: u64,
	output: &mut W,
) -> Result<u64> {
	let mut written_bytes = 0;
	if let Some(chunk_no) = chunk_size_map.chunkmap().keys().max() {
		main_footer_chunk_size_map.insert(*chunk_no, current_segment_no);
		segment_footer.chunk_size_map_table.insert(*chunk_no, written_bytes + seek_value);
		written_bytes += output.write(&chunk_size_map.encode_directly())? as u64;
		chunk_size_map.flush();
	}
	Ok(written_bytes)
}

fn flush_chunk_size_map_checked<W: Write>(
	chunk_size_map: &mut ChunkSizeMap,
	main_footer_chunk_size_map: &mut BTreeMap<u64, u64>,
	segment_footer: &mut SegmentFooter,
	current_segment_no: u64,
	seek_value: u64,
	output: &mut W,
) -> Result<u64> {
	let mut written_bytes = 0;
	if chunk_size_map.is_full() {
		written_bytes += flush_chunk_size_map(
			chunk_size_map, 
			main_footer_chunk_size_map, 
			segment_footer, 
			current_segment_no, 
			seek_value, 
			output)?;
	}
	Ok(written_bytes)
}

fn flush_chunk_flags_map<W: Write>(
	chunk_flags_map: &mut ChunkFlagMap,
	main_footer_chunk_flags_map: &mut BTreeMap<u64, u64>,
	segment_footer: &mut SegmentFooter,
	current_segment_no: u64,
	seek_value: u64,
	output: &mut W,
) -> Result<u64> {
	let mut written_bytes = 0;
	if let Some(chunk_no) = chunk_flags_map.chunkmap().keys().max() {
		main_footer_chunk_flags_map.insert(*chunk_no, current_segment_no);
		segment_footer.chunk_flags_map_table.insert(*chunk_no, written_bytes + seek_value);
		written_bytes += output.write(&chunk_flags_map.encode_directly())? as u64;
		chunk_flags_map.flush();
	}
	Ok(written_bytes)
}

fn flush_chunk_flags_map_checked<W: Write>(
	chunk_flags_map: &mut ChunkFlagMap,
	main_footer_chunk_flags_map: &mut BTreeMap<u64, u64>,
	segment_footer: &mut SegmentFooter,
	current_segment_no: u64,
	seek_value: u64,
	output: &mut W,
) -> Result<u64> {
	let mut written_bytes = 0;
	if chunk_flags_map.is_full() {
		written_bytes += flush_chunk_flags_map(
			chunk_flags_map, 
			main_footer_chunk_flags_map, 
			segment_footer, 
			current_segment_no, 
			seek_value, 
			output)?;
	}
	Ok(written_bytes)
}

fn flush_chunk_crc_map<W: Write>(
	chunk_crc_map: &mut ChunkCRCMap,
	main_footer_chunk_crc_map: &mut BTreeMap<u64, u64>,
	segment_footer: &mut SegmentFooter,
	current_segment_no: u64,
	seek_value: u64,
	output: &mut W,
) -> Result<u64> {
	let mut written_bytes = 0;
	if let Some(chunk_no) = chunk_crc_map.chunkmap().keys().max() {
		main_footer_chunk_crc_map.insert(*chunk_no, current_segment_no);
		segment_footer.chunk_crc_map_table.insert(*chunk_no, written_bytes + seek_value);
		written_bytes += output.write(&chunk_crc_map.encode_directly())? as u64;
		chunk_crc_map.flush();
	}
	Ok(written_bytes)
}

fn flush_chunk_crc_map_checked<W: Write>(
	chunk_crc_map: &mut ChunkCRCMap,
	main_footer_chunk_crc_map: &mut BTreeMap<u64, u64>,
	segment_footer: &mut SegmentFooter,
	current_segment_no: u64,
	seek_value: u64,
	output: &mut W,
) -> Result<u64> {
	let mut written_bytes = 0;
	if chunk_crc_map.is_full() {
		written_bytes += flush_chunk_crc_map(
			chunk_crc_map, 
			main_footer_chunk_crc_map, 
			segment_footer, 
			current_segment_no, 
			seek_value, 
			output)?;
	}
	Ok(written_bytes)
}