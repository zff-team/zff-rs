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
}

impl<R: Read + Seek> ZffObjectReaderVirtualLogical<R> {
    /// Initialize the [ZffObjectReaderLogical] with the recommended set of metadata which will be stored in memory.
	pub fn new(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Result<Self> {
			Self::with_obj_metadata(object_no, metadata)
	}
    
    /// creates a new [ZffObjectReaderVirtual] with the given metadata.
	fn with_obj_metadata(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Result<Self> {
        let object_header = metadata.object_header(&object_no).unwrap().clone();
		let object_footer = match metadata.object_footer(&object_no) {
			Some(ObjectFooter::VirtualLogical(footer)) => footer.clone(),
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
		}

		#[cfg(feature = "log")]
		debug!("{} files were successfully initialized for virtual logical object {}.", files.len(), object_header.object_number);

        Ok(Self {
            metadata,
            object_header,
            object_footer,
            active_file: 0,
            files,
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
		match self.files.get(&self.active_file) {
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

impl<R: Read + Seek> Read for ZffObjectReaderVirtualLogical<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        todo!()
    }
}

impl<R: Read + Seek> Seek for ZffObjectReaderVirtualLogical<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        todo!()
    }
}