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
	files: HashMap<u64, FileMetadata>,//<filenumber, metadata>,
}

impl<R: Read + Seek> ZffObjectReaderLogical<R> {
	/*/// Initialize the [ZffObjectReaderLogical] with a minimal set of (the absolutly required) metadata which will be stored in memory.
	pub fn with_obj_metadata_minimal(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Result<Self> {
		Self::with_obj_metadata(object_no, metadata, PreloadDegree::Minimal)
	}*/

	/// Initialize the [ZffObjectReaderLogical] with the recommended set of metadata which will be stored in memory.
	pub fn with_obj_metadata_recommended(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Result<Self> {
			Self::with_obj_metadata(object_no, metadata, PreloadDegree::Recommended)
	}

	/*/// Initialize the [ZffObjectReaderLogical] which will store all metadata in memory.
	pub fn with_obj_metadata_all(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Result<Self> {
			Self::with_obj_metadata(object_no, metadata, PreloadDegree::All)
	}*/

	fn with_obj_metadata(object_no: u64, metadata: ArcZffReaderMetadata<R>, degree_value: PreloadDegree) -> Result<Self> {
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

		// reads all file header and appropriate footer and fill the files-map. Sets the File number 1 active.
		let mut files = HashMap::new();
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
			let metadata = match degree_value {
				//PreloadDegree::Minimal => FileMetadata::with_header_minimal(&fileheader, &filefooter),
				PreloadDegree::Recommended => FileMetadata::with_header_recommended(&fileheader, &filefooter),
				//PreloadDegree::All => FileMetadata::with_header_all(&fileheader, &filefooter),
			};
			files.insert(*filenumber, metadata);
		}

		#[cfg(feature = "log")]
		debug!("{} files were successfully initialized for logical object {}.", files.len(), object_header.object_number);

		Ok(Self {
			metadata,
			object_header,
			object_footer,
			active_file: 1,
			files,
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

	/// Returns the appropriate [FileHeader](crate::header::FileHeader) of the current active file.
	pub fn current_fileheader(&self) -> Result<FileHeader> {
		let header_segment_number = match self.object_footer.file_header_segment_numbers().get(&self.active_file) {
			Some(no) => no,
			None => return Err(ZffError::new(
				ZffErrorKind::Missing,
				format!("{ERROR_MISSING_FILE_NUMBER}{}", self.active_file)))
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

	/// Returns the appropriate [FileFooter](crate::footer::FileFooter) of the current active file.
	pub fn current_filefooter(&self) -> Result<FileFooter> {
		let footer_segment_number = match self.object_footer.file_footer_segment_numbers().get(&self.active_file) {
			Some(no) => no,
			None => return Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("{ERROR_MISSING_FILE_NUMBER}{}", self.active_file)))
		};
		let footer_offset = match self.object_footer.file_footer_offsets().get(&self.active_file) {
			Some(offset) => offset,
			None => return Err(ZffError::new(
				ZffErrorKind::EncodingError, 
				format!("{ERROR_UNREADABLE_FILE_FOOTER_OFFSET_NO}{} of object {}", 
				self.active_file, 
				self.object_header.object_number))),
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
		match self.metadata.segments.write().unwrap().get_mut(footer_segment_number) {
			None => Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("{ERROR_MISSING_SEGMENT}{footer_segment_number}"))),
			Some(segment) => {
				segment.seek(SeekFrom::Start(*footer_offset))?;
				//check encryption
				if let Some(enc_info) = &enc_info {
					Ok(FileFooter::decode_encrypted_footer_with_key(segment, enc_info)?)
				} else {
					Ok(FileFooter::decode_directly(segment)?)
				}
			}
		}
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
		match self.files.get(&self.active_file) {
			Some(metadata) => Ok(metadata),
			None => Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("{ERROR_MISSING_FILE_NUMBER}{}", self.active_file)))
		}
	}

	/// Returns a Reference of the inner files Hashmap
	pub(crate) fn files(&self) -> &HashMap<u64, FileMetadata> {
		&self.files
	}
}

impl<R: Read + Seek> Read for ZffObjectReaderLogical<R> {
	fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
		let active_filemetadata = match self.files.get_mut(&self.active_file) {
			Some(metadata) => metadata,
			None => return Err(
				std::io::Error::new(
					std::io::ErrorKind::Other, 
					format!("{ERROR_MISSING_FILE_NUMBER}{}", self.active_file))),
		};
		let chunk_size = self.object_header.chunk_size;
		let first_chunk_number = active_filemetadata.first_chunk_number;
		let last_chunk_number = first_chunk_number + active_filemetadata.number_of_chunks - 1;
		let mut current_chunk_number = (first_chunk_number * chunk_size + active_filemetadata.position) / chunk_size;
		let mut inner_position = (active_filemetadata.position % chunk_size) as usize; // the inner chunk position
		let mut read_bytes = 0; // number of bytes which are written to buffer
		loop {
			if read_bytes == buffer.len() || current_chunk_number > last_chunk_number {
				break;
			}

			let chunk_data = if let Some(samebyte) = self.metadata.preloaded_chunkmaps.read().unwrap().get_samebyte(current_chunk_number) {
				vec![samebyte; chunk_size as usize]
			} else {
				let object_no = &self.object_header.object_number;
				get_chunk_data(object_no, Arc::clone(&self.metadata), current_chunk_number)?
			};
			let mut cursor = Cursor::new(&chunk_data[inner_position..]);
			read_bytes += cursor.read(&mut buffer[read_bytes..])?;
			inner_position = 0;
			current_chunk_number += 1;
		}
		active_filemetadata.position += read_bytes as u64;
		Ok(read_bytes)
	}
}

impl<R: Read + Seek> Seek for ZffObjectReaderLogical<R> {
	fn seek(&mut self, seek_from: SeekFrom) -> std::result::Result<u64, std::io::Error> {

		let active_filemetadata = match self.files.get_mut(&self.active_file) {
			Some(metadata) => metadata,
			None => return Err(
				std::io::Error::new(
					std::io::ErrorKind::Other, 
					format!("{ERROR_MISSING_FILE_NUMBER}{}", self.active_file))),
		};

		match seek_from {
			SeekFrom::Start(value) => {
				active_filemetadata.position = value;
			},
			SeekFrom::Current(value) => if active_filemetadata.position as i64 + value < 0 {
				return Err(std::io::Error::new(std::io::ErrorKind::Other, ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))
			} else if value >= 0 {
					active_filemetadata.position += value as u64;
			} else {
				active_filemetadata.position -= value as u64;
			},
			SeekFrom::End(value) => if active_filemetadata.position as i64 + value < 0 {
				return Err(std::io::Error::new(std::io::ErrorKind::Other, ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))
			} else if value >= 0 {
					active_filemetadata.position = active_filemetadata.length_of_data + value as u64;
			} else {
				active_filemetadata.position = active_filemetadata.length_of_data - value as u64;
			},
		}
		Ok(active_filemetadata.position)
	}
}