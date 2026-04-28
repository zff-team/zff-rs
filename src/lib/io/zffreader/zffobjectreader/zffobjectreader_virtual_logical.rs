// - Parent
use super::*;

/// A reader which contains the appropriate metadata of a logical object 
/// (e.g. the appropriate [ObjectHeader](crate::header::ObjectHeader) and [ObjectFooter](crate::footer::ObjectFooter)).
#[derive(Debug)]
pub(crate) struct ZffObjectReaderVirtualLogical<R: Read + Seek> {
	metadata: ArcZffReaderMetadata<R>,
	object_header: ObjectHeader,
	object_footer: ObjectFooterVirtualLogical,
    active_file: u64, // filenumber of active file
    files: HashMap<u64, FileMetadata>, //<filenumber, metadata>,
	file_positions: HashMap<u64, u64>,
	// this is also available via the ArcZffReaderMetadata, but this one is much more convenient to access. :)
	passive_object_filemetadata: HashMap<u64, Arc<HashMap<u64, FileMetadata>>>, //<object_number, <filenumber, Metadata>>,
	// The filemaps will be stored in a vectorized format to perform efficient searches.
	filemaps: HashMap<u64, Vec<(u64, VirtualLogicalFileExtent)>> // (filenumber, vectorized_filemap)
}

impl<R: Read + Seek> ZffObjectReaderVirtualLogical<R> {
    /// Initialize the [ZffObjectReaderLogical] with the recommended set of metadata which will be stored in memory.
	pub fn new(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Result<Self> {
			Self::with_obj_metadata(object_no, metadata)
	}

	/// Returns a reference of the vectorized VLFM for the given filenumber, if exists in map.
	fn vectorized_vlfm(&self, filenumber: u64) -> Option<&Vec<(u64, VirtualLogicalFileExtent)>> {
		self.filemaps.get(&filenumber)
	}

	/// Returns the VLFM for the given filenumber by reading them directly from segment.
	fn read_virtual_logical_filemap(&self, filenumber: u64) -> Result<VirtualLogicalFileMap> {
		let filemetadata = self.filemetadata_by_filenumber(filenumber)?;
		let filemap_position = filemetadata.filemap_position()?;
		let enc_info = EncryptionInformation::try_from(&self.object_header).ok();

		let vlfm = {
			let mut segments = self.metadata.segments.write().unwrap();
			match segments.get_mut(&filemap_position.segment_no) {
				None => return Err(ZffError::new(
					ZffErrorKind::Missing, 
					format!("{ERROR_MISSING_SEGMENT}{}", filemap_position.segment_no))),
				Some(segment) => {
					segment.seek(SeekFrom::Start(filemap_position.offset))?;
					//check encryption
					if let Some(enc_info) = &enc_info {
						VirtualLogicalFileMap::decode_encrypted_footer_with_key(segment, enc_info)?
					} else {
						VirtualLogicalFileMap::decode_directly(segment)?
					}
				}
			}
		};
		Ok(vlfm)
	}

	/// Initialze a single filemap (for internal use only - will be used for caching)
	fn initialize_filemap(&mut self, filenumber: u64) -> Result<()> {
		let vlfm = self.read_virtual_logical_filemap(filenumber)?;
		self.filemaps.insert(filenumber, vlfm.into());

		Ok(())
	}

	/// Pre-initialize all filemaps at cost of memory.
	pub fn initialize_filemaps(&mut self) -> Result<()> {
		// Checks if memory space is sufficient.
		self.filemaps.try_reserve(self.object_footer.file_header_segment_numbers.len())?;
		for filenumber in self.files.keys() {
			let vlfm = self.read_virtual_logical_filemap(*filenumber)?;
			self.filemaps.insert(*filenumber, vlfm.into());
		}
		Ok(())
	}
    
    /// creates a new [ZffObjectReaderVirtual] with the given metadata.
	fn with_obj_metadata(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Result<Self> {
        let object_header = metadata.object_header(&object_no).unwrap().clone();
		let object_footer = match metadata.object_footer(&object_no) {
			Some(ObjectFooter::VirtualLogical(footer)) => footer.clone(),
			_ => unreachable!(), // already checked before in zffreader::initialize_unencrypted_object_reader();
		};
		let mut passive_object_filemetadata = HashMap::new();
		for passive_object_number in &object_footer.passive_objects {
			let metadata_guard = metadata.object_metadata.read()?;
			let obj_metadata = match metadata_guard.get(passive_object_number) {
				Some(obj_metadata) => obj_metadata,
				None => return Err(ZffError::new(
					ZffErrorKind::Missing, 
					format!("{ERROR_ZFFREADER_MISSING_PASSIVE_OBJECT}{passive_object_number}"))),
			};
			let files = match &obj_metadata.files {
				Some(files) => files,
				None => return Err(ZffError::new(
					ZffErrorKind::Missing, 
					format!("{ERROR_ZFFREADER_MISSING_PASSIVE_OBJECT}{passive_object_number}"))),
			};
			passive_object_filemetadata.insert(*passive_object_number, Arc::clone(files));
		}

		let filemaps = HashMap::new();

        let enc_info = if let Some(encryption_header) = &object_header.encryption_header {
			let key = match encryption_header.get_encryption_key() {
				Some(key) => key,
				None => return Err(ZffError::new(
					ZffErrorKind::EncryptionError, 
					ERROR_MISSING_ENCRYPTION_HEADER_KEY)),
			};
			Some(EncryptionInformation::new(key, encryption_header.algorithm.clone()))
		} else {
			None
		};

        // reads all file header and appropriate footer and fill the files-map/file_positions_map. Sets the File number 1 active.
		let mut files = HashMap::new();
		let mut file_positions = HashMap::new();
		for (filenumber, header_segment_number) in &object_footer.file_header_segment_numbers {
			#[cfg(feature = "log")]
			debug!("Initialize file {filenumber}");
			let header_offset = match object_footer.file_header_offsets.get(&filenumber) {
				Some(offset) => offset,
				None => return Err(ZffError::new(ZffErrorKind::Invalid, ERROR_MALFORMED_SEGMENT)),
			};
			let (footer_segment_number, footer_offset) = match object_footer.file_footer_segment_numbers.get(&filenumber) {
				None => return Err(ZffError::new(ZffErrorKind::Invalid, ERROR_MALFORMED_SEGMENT)),
				Some(segment_no) => match object_footer.file_footer_offsets.get(&filenumber) {
					None => return Err(ZffError::new(ZffErrorKind::Invalid, ERROR_MALFORMED_SEGMENT)),
					Some(offset) => (segment_no, offset),
				}
			};
			let mut segments = metadata.segments.write().unwrap();
			let fileheader = match segments.get_mut(&header_segment_number) {
				None => return Err(ZffError::new(
					ZffErrorKind::Missing, 
					format!("{ERROR_MISSING_SEGMENT}{header_segment_number}"))),
				Some(segment) => {
					segment.seek(SeekFrom::Start(*header_offset))?;
					//check encryption
					if let Some(enc_info) = &enc_info {
						FileHeader::decode_encrypted_header_with_key(segment, enc_info)?
					} else {
						FileHeader::decode_directly(segment)?
					}
				}
			};
			let filefooter = match segments.get_mut(footer_segment_number) {
				None => return Err(ZffError::new(
					ZffErrorKind::Missing, 
					format!("{ERROR_MISSING_SEGMENT}{footer_segment_number}"))),
				Some(segment) => {
					segment.seek(SeekFrom::Start(*footer_offset))?;
					//check encryption
					if let Some(enc_info) = &enc_info {
						VirtualFileFooter::decode_encrypted_footer_with_key(segment, enc_info)?
					} else {
						VirtualFileFooter::decode_directly(segment)?
					}
				}
			};
			let metadata = FileMetadata::with_virtual_file_footer(fileheader, filefooter);
			files.insert(*filenumber, metadata);
			file_positions.insert(*filenumber, 0);
		}

		#[cfg(feature = "log")]
		debug!("{} files were successfully initialized for virtual logical object {}.", files.len(), object_header.object_number);

        Ok(Self {
            metadata,
            object_header,
            object_footer,
            active_file: 1,
            files,
			file_positions,
			passive_object_filemetadata,
			filemaps,
        })
    }

	/// Sets the file of the appropriate filenumber active.
	/// # Error
	/// fails if no appropriate file for the given filenumber exists.
	pub fn set_active_file(&mut self, filenumber: u64) -> Result<()> {
		match self.files.get(&filenumber) {
			Some(_) => self.active_file = filenumber,
			None => return Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("{ERROR_MISSING_FILE_NUMBER}{filenumber}")))
		}
		Ok(())
	}

	/// Returns the [FileMetadata] of the active file.
	/// # Error
	/// Fails if no valid file is set as the active one.
	pub(crate) fn filemetadata(&self) -> Result<&FileMetadata> {
		self.filemetadata_by_filenumber(self.active_file)
	}

	pub(crate) fn filemetadata_by_filenumber(&self, filenumber: u64) -> Result<&FileMetadata> {
		match self.files.get(&filenumber) {
			Some(metadata) => Ok(metadata),
			None => Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("{ERROR_MISSING_FILE_NUMBER}{}", self.active_file)))
		}
	}

    /// Returns a reference of the appropriate [ObjectHeader](crate::header::ObjectHeader).
	pub(crate) fn object_header_ref(&self) -> &ObjectHeader {
		&self.object_header
	}

    /// Returns the appropriate [ObjectFooter](crate::footer::ObjectFooter).
	pub(crate) fn object_footer(&self) -> ObjectFooter {
		ObjectFooter::VirtualLogical(self.object_footer.clone())
	}
}

/// Reads from current active file.
impl<R: Read + Seek> Read for ZffObjectReaderVirtualLogical<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
		let mut read_bytes = 0;
        if self.files.get(&self.active_file).is_none() {
			return Err(
				std::io::Error::new(
					std::io::ErrorKind::Other, 
					format!("{ERROR_MISSING_FILE_NUMBER}{}", self.active_file)));
		};
		//unwrap is safe here: self.files and self.file_positions are both filled by new()-function.
		let mut position_cpy = *self.file_positions.get(&self.active_file).unwrap();
		let buf_len = buffer.len();
		loop {
			if read_bytes == buf_len {
				break;
			}
			let mut remove_filemap_init = false;
			let vlfe_option = match self.vectorized_vlfm(self.active_file) {
				Some(vec_vlfm) => floor_vec_entry(vec_vlfm, position_cpy),
				None => {
					// initializes the affected filemap into memory but removes it again at the end.
					// this is a huge performance impact, but keeps the memory in a clean state
					if let Err(_) = self.initialize_filemap(self.active_file) {
					return Err(
								std::io::Error::new(
									std::io::ErrorKind::Other, 
									format!("{ERROR_ZFFREADER_MISSING_VLFM}{}", self.active_file)))
					};
					remove_filemap_init = true;
					// unwrap should be safe at this point, we already have initialized the appropriate filemap :)
					floor_vec_entry(self.vectorized_vlfm(self.active_file).unwrap(), position_cpy)
				},
			};
			let (virtual_offset_start, vlfe) = match vlfe_option {
				Some(vlfe) => vlfe,
				None => return Err(
								std::io::Error::new(
									std::io::ErrorKind::Other, 
									format!("{ERROR_ZFFREADER_MISSING_VALUE_VLFM}{}", position_cpy)))
			};

			if position_cpy >= virtual_offset_start+vlfe.length {
				if remove_filemap_init {
					self.filemaps.remove(&self.active_file);
				}
				break;
			}

			let mut relative_position = (position_cpy - virtual_offset_start) as usize;

			let source_chunk_size = {
				let metadata_guard = self.metadata.object_metadata.read().unwrap();
				match metadata_guard.get(&vlfe.source_object_number) {
					Some(obj_metadata) => obj_metadata.header.chunk_size,
					None => return Err(
								std::io::Error::new(
									std::io::ErrorKind::Other, 
									format!("{ERROR_ZFFREADER_MISSING_PASSIVE_OBJECT}{}", vlfe.source_object_number)))
				}
			};
			let metadata_guard = self.metadata.object_metadata.read().unwrap();
			match metadata_guard.get(&vlfe.source_object_number) {
				Some(obj_metadata) => match &obj_metadata.footer {
					ObjectFooter::Logical(_) => {
						let source_filemetadata = match self.passive_object_filemetadata
															.get(&vlfe.source_object_number)
															.and_then(|files| files.get(&vlfe.source_filenumber)) {
							Some(filemetadata) => filemetadata,
							None => return Err(
											std::io::Error::new(
												std::io::ErrorKind::Other, 
												format!("{ERROR_ZFFREADER_MISSING_PASSIVE_OBJECT}{}", vlfe.source_object_number)))
						};
						let first_chunk_number = match source_filemetadata.first_chunk_number() {
							Some(first_chunk_no) => first_chunk_no,
							None => return Err(
											std::io::Error::new(
												std::io::ErrorKind::Other, 
												format!("{ERROR_MALFORMED_SEGMENT}")))
						};
						let last_chunk_no = match source_filemetadata.number_of_chunks() {
							Some(number_of_chunks) => first_chunk_number + number_of_chunks -1,
							None => return Err(
											std::io::Error::new(
												std::io::ErrorKind::Other, 
												format!("{ERROR_MALFORMED_SEGMENT}")))
						}; 
						let mut current_chunk_number = {
							let source_position_absolute = vlfe.source_offset + relative_position as u64;
							(first_chunk_number * source_chunk_size + source_position_absolute) / source_chunk_size
						};

						loop {
							if read_bytes == buf_len || current_chunk_number > last_chunk_no {
								position_cpy += read_bytes as u64;
								break;
							}
							let chunk_data = if let Some(samebyte) = self.metadata.preloaded_chunkmaps
																					.read().unwrap().get_samebyte(current_chunk_number) {
								vec![samebyte; source_chunk_size as usize]
							} else {
								let object_no = &self.object_header.object_number;
								get_chunk_data(object_no, Arc::clone(&self.metadata), current_chunk_number)?
							};
							let mut cursor = Cursor::new(&chunk_data[relative_position..]);
							relative_position = 0;
							read_bytes += cursor.read(&mut buffer[read_bytes..])?;
							current_chunk_number += 1;
						}
					},
					ObjectFooter::Physical(footer) => {
						let source_position_absolute = vlfe.source_offset + relative_position as u64;
						let mut current_chunk_number = (footer.first_chunk_number * source_chunk_size + source_position_absolute) / source_chunk_size;
						let last_chunk_no = footer.first_chunk_number + footer.number_of_chunks  - 1;
						loop {
							if read_bytes == buf_len || current_chunk_number > last_chunk_no {
								position_cpy += read_bytes as u64;
								break;
							}

							let chunk_data = if let Some(samebyte) = self.metadata.preloaded_chunkmaps.read().unwrap().get_samebyte(current_chunk_number) {
								vec![samebyte; source_chunk_size as usize]
							} else {
								let object_no = &self.object_header.object_number;
								get_chunk_data(object_no, Arc::clone(&self.metadata), current_chunk_number)?
							};
							let mut cursor = Cursor::new(&chunk_data[relative_position..]);
							read_bytes += cursor.read(&mut buffer[read_bytes..])?;
							relative_position = 0;
							current_chunk_number += 1;
						}
					},
					//TODO: I should check if I could support Virtual/VirtualLogical objects here too.
					_ => return Err(
									std::io::Error::new(
										std::io::ErrorKind::Other, 
										format!("{ERROR_ZFFREADER_OPERATION_VIRTUAL_LOGICAL_OBJECT}{}", vlfe.source_object_number)))
				},
				None => return Err(
							std::io::Error::new(
								std::io::ErrorKind::Other, 
								format!("{ERROR_ZFFREADER_MISSING_PASSIVE_OBJECT}{}", vlfe.source_object_number)))
			}
			if remove_filemap_init {
				self.filemaps.remove(&self.active_file);
			}
		}
		if let Some(position) = self.file_positions.get_mut(&self.active_file) {
			*position += read_bytes as u64;
		}
		Ok(read_bytes)
    }
}

/// Seeks in current active file.
impl<R: Read + Seek> Seek for ZffObjectReaderVirtualLogical<R> {
    fn seek(&mut self, seek_from: SeekFrom) -> std::io::Result<u64> {
        let position = match self.file_positions.get_mut(&self.active_file) {
			Some(metadata) => metadata,
			None => return Err(
				std::io::Error::new(
					std::io::ErrorKind::Other, 
					format!("{ERROR_MISSING_FILE_NUMBER}{}", self.active_file))),
		};
		let filemetadata = match self.files.get(&self.active_file) {
			Some(metadata) => metadata,
			None => return Err(
				std::io::Error::new(
					std::io::ErrorKind::Other, 
					format!("{ERROR_MISSING_FILE_NUMBER}{}", self.active_file))),
		};

		match seek_from {
			SeekFrom::Start(value) => {
				*position = value;
			},
			SeekFrom::Current(value) => if *position as i64 + value < 0 {
				return Err(std::io::Error::new(std::io::ErrorKind::Other, ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))
			} else if value >= 0 {
					*position += value as u64;
			} else {
				*position -= value as u64;
			},
			SeekFrom::End(value) => if *position as i64 + value < 0 {
				return Err(std::io::Error::new(std::io::ErrorKind::Other, ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))
			} else if value >= 0 {
					*position = filemetadata.length_of_data() + value as u64;
			} else {
				*position = filemetadata.length_of_data() - value as u64;
			},
		}
		Ok(*position)
    }
}