// - STD
use std::io::Error as IoError;

// - Parent
use super::*;

/// A reader which contains the appropriate metadata of a logical object 
/// (e.g. the appropriate [ObjectHeader](crate::header::ObjectHeader) and [ObjectFooter](crate::footer::ObjectFooter)).
#[derive(Debug)]
pub(crate) struct ZffObjectReaderLogical<R: Read + Seek> {
	metadata: ArcZffReaderMetadata<R>,
	object_header: ObjectHeader,
	object_footer: ObjectFooterLogical,
	active_file: u64, // filenumber of active file
	file_positions: HashMap<u64, u64>, //<filenumber, position>
	// this one is "redundant", the data is already available via the ArcZffReaderMetadata - but you can much more easier
	// access them with that additional hashmap.
	files: Arc<HashMap<u64, FileMetadata>>, //<filenumber, FileMetadata>
	reader_cache: Cursor<Vec<u8>>, //cache which holds the current chunk content (for performance purposes)
}

impl<R: Read + Seek> ZffObjectReaderLogical<R> {
	/// Initialize the [ZffObjectReaderLogical].
	pub fn new(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Result<Self> {
			Self::with_obj_metadata(object_no, metadata)
	}

	/// Returns the appropriate [FileHeader](crate::header::FileHeader) of the current active file.
	pub fn current_fileheader(&self) -> Result<FileHeader> {
		let header_segment_number = match self.object_footer.file_header_segment_numbers().get(&self.active_file) {
			Some(no) => no,
			None => return Err(ZffError::new(
				ZffErrorKind::Missing,
				format!("(current_fileheader) {ERROR_MISSING_FILE_NUMBER}{}", self.active_file)))
		};
		let header_offset = match self.object_footer.file_header_offsets().get(&self.active_file) {
			Some(offset) => offset,
			None => return Err(ZffError::new(
				ZffErrorKind::EncodingError, 
				format!("{ERROR_UNREADABLE_OBJECT_HEADER_OFFSET_NO}{}", self.object_header.object_number))),
		};
		let enc_info = if let Some(encryption_header) = &self.object_header.encryption_header {
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
		match self.metadata.segments.write().unwrap().get_mut(header_segment_number) {
			None => Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("{ERROR_MISSING_SEGMENT}{header_segment_number}"))),
			Some(segment) => {
				segment.seek(SeekFrom::Start(*header_offset))?;
				//check encryption
				if let Some(enc_info) = &enc_info {
					Ok(FileHeader::decode_encrypted_header_with_key(segment, enc_info)?)
				} else {
					Ok(FileHeader::decode_directly(segment)?)
				}
			}
		}
	}

	fn with_obj_metadata(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Result<Self> {
		#[cfg(feature = "log")]
		debug!("Initialize logical object {}", object_no);
		let object_header = metadata.object_header(&object_no).unwrap().clone();
		let object_footer = match metadata.object_footer(&object_no) {
			Some(ObjectFooter::Logical(footer)) => footer.clone(),
			_ => unreachable!(), // already checked before in zffreader::initialize_unencrypted_object_reader();
		};

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

		// reads all file header and appropriate footer and fill the files-map/file_positions-map. Sets the File number 1 active.
		let mut files = HashMap::new();
		let mut file_positions = HashMap::new();
		for (filenumber, header_segment_number) in object_footer.file_header_segment_numbers() {
			#[cfg(feature = "log")]
			debug!("Initialize file {filenumber}");
			let header_offset = match object_footer.file_header_offsets().get(filenumber) {
				Some(offset) => offset,
				None => return Err(ZffError::new(ZffErrorKind::Invalid, ERROR_MALFORMED_SEGMENT)),
			};
			let (footer_segment_number, footer_offset) = match object_footer.file_footer_segment_numbers().get(filenumber) {
				None => return Err(ZffError::new(ZffErrorKind::Invalid, ERROR_MALFORMED_SEGMENT)),
				Some(segment_no) => match object_footer.file_footer_offsets().get(filenumber) {
					None => return Err(ZffError::new(ZffErrorKind::Invalid, ERROR_MALFORMED_SEGMENT)),
					Some(offset) => (segment_no, offset),
				}
			};
			let mut segments = metadata.segments.write().unwrap();
			let fileheader = match segments.get_mut(header_segment_number) {
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
						FileFooter::decode_encrypted_footer_with_key(segment, enc_info)?
					} else {
						FileFooter::decode_directly(segment)?
					}
				}
			};
			let metadata = FileMetadata::with_file_footer(fileheader, filefooter);
			files.insert(*filenumber, metadata);
			file_positions.insert(*filenumber, 0);
		}

		let files = Arc::new(files);
		#[cfg(feature = "log")]
		debug!("{} files were successfully initialized for logical object {}.", files.len(), object_header.object_number);
		{
			let mut metadata_guard = metadata.object_metadata.write().unwrap();
			// unwrap is safe here, we've already used this before to obtain the appropriate object header and footer ;)
			metadata_guard.get_mut(&object_no).unwrap().files = Some(Arc::clone(&files));
		}

		Ok(Self {
			metadata,
			object_header,
			object_footer,
			active_file: 1,
			file_positions,
			files,
			reader_cache: Cursor::new(Vec::new()),
		})
	}

	/// Returns a reference of the appropriate [ObjectHeader](crate::header::ObjectHeader).
	pub(crate) fn object_header_ref(&self) -> &ObjectHeader {
		&self.object_header
	}

	/// Returns the appropriate [ObjectFooter](crate::footer::ObjectFooter).
	pub(crate) fn object_footer(&self) -> ObjectFooter {
		ObjectFooter::Logical(self.object_footer.clone())
	}

	/// Sets the file of the appropriate filenumber active.
	/// # Error
	/// fails if no appropriate file for the given filenumber exists.
	pub fn set_active_file(&mut self, filenumber: u64) -> Result<()> {
		match self.files.get(&filenumber) {
			Some(_) => self.active_file = filenumber,
			None => return Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("(set_active_file) {ERROR_MISSING_FILE_NUMBER}{filenumber}")))
		}
		self.reader_cache.get_mut().clear();
		Ok(())
	}

	/// Returns the [FileMetadata] of the active file.
	/// # Error
	/// Fails if no valid file is set as the active one.
	pub(crate) fn filemetadata(&self) -> Result<&FileMetadata> {
		match self.files.get(&self.active_file) {
			Some(metadata) => Ok(metadata),
			None => Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("(filemetadata) {ERROR_MISSING_FILE_NUMBER}{}", self.active_file)))
		}
	}

	/// Returns a Reference of the inner files Hashmap
	pub(crate) fn files(&self) -> &HashMap<u64, FileMetadata> {
		&self.files
	}

	// Returns true if cache would filled, false if cache is empty (end of reader is reached).
	fn refill_reader_cache(&mut self) -> std::io::Result<bool> {
		let filemetadata = self.files.get(&self.active_file).ok_or(IoError::other(format!("(refill_reader_cache) {ERROR_MISSING_FILE_NUMBER}{}", self.active_file)))?;
		//unwrap is safe here: self.files and self.file_positions are both filled by new()-function.
		let position = self.file_positions.get_mut(&self.active_file).unwrap();

		if *position >= filemetadata.length_of_data() {
			return Ok(false);
		}

		let chunk_size = self.object_header.chunk_size;
		//unwrap is safe here: we've never initialized FileMetadata for ZffObjectReaderLogical with ::with_virtual_file_footer().
		let first_chunk_number = filemetadata.first_chunk_number().unwrap();
		let last_chunk_number = first_chunk_number + filemetadata.number_of_chunks().unwrap() - 1;
		let current_chunk_number = (first_chunk_number * chunk_size + *position) / chunk_size;
		let inner_position = (*position % chunk_size) as usize; // the inner chunk position

		if current_chunk_number > last_chunk_number {
			return Ok(false)
		}
		let chunk_data = if let Some(samebyte) = self.metadata.preloaded_chunkmaps.read().unwrap().get_samebyte(current_chunk_number) {
			vec![samebyte; chunk_size as usize]
		} else {
			let object_no = &self.object_header.object_number;
			get_chunk_data(object_no, Arc::clone(&self.metadata), current_chunk_number)?
		};
		{
			self.reader_cache.set_position(0);
			let inner = self.reader_cache.get_mut();
			inner.clear();
			inner.extend_from_slice(&chunk_data[inner_position..]);
		}
		Ok(true)
	}
}

impl<R: Read + Seek> Read for ZffObjectReaderLogical<R> {
	fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
		let mut read_bytes = 0;
		while read_bytes < buffer.len() {
            if self.reader_cache.position() as usize >= self.reader_cache.get_ref().len() &&
			!self.refill_reader_cache()? {
					break;
			}
			let written = self.reader_cache.read(&mut buffer[read_bytes..])?;
            read_bytes += written;
			// unwrap is safe here: we have called refill_reader_cache() before which calls self.file.get(&self.acitve_file).
			*self.file_positions.get_mut(&self.active_file).unwrap() += written as u64;
        }
		Ok(read_bytes)
	}
}

impl<R: Read + Seek> Seek for ZffObjectReaderLogical<R> {
	fn seek(&mut self, seek_from: SeekFrom) -> std::result::Result<u64, std::io::Error> {
		let filemetadata = match self.files.get(&self.active_file) {
			Some(metadata) => metadata,
			None => return Err(
				std::io::Error::other(
					format!("{ERROR_MISSING_FILE_NUMBER}{}", self.active_file))),
		};
		//unwrap is safe here: self.files and self.file_positions are both filled by new()-function.
		let position = self.file_positions.get_mut(&self.active_file).unwrap();

		match seek_from {
			SeekFrom::Start(value) => {
				*position = value;
			},
			SeekFrom::Current(value) => if *position as i64 + value < 0 {
				return Err(std::io::Error::other(ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))
			} else if value >= 0 {
					*position += value as u64;
			} else {
				*position -= value as u64;
			},
			SeekFrom::End(value) => if *position as i64 + value < 0 {
				return Err(std::io::Error::other(ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))
			} else if value >= 0 {
					*position = filemetadata.length_of_data() + value as u64;
			} else {
				*position = filemetadata.length_of_data() - value as u64;
			},
		}
		Ok(*position)
	}
}