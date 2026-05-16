// - STD
use std::io::Error as IoError;

// - Parent
use super::*;

/// A reader which contains the appropriate metadata of a logical object 
/// (e.g. the appropriate [ObjectHeader](crate::header::ObjectHeader) and [ObjectFooter](crate::footer::ObjectFooter)).
#[derive(Debug)]
pub(crate) struct ZffObjectReaderVirtual<R: Read + Seek> {
	metadata: ArcZffReaderMetadata<R>,
	object_header: ObjectHeader,
	object_footer: ObjectFooterVirtual,
    active_file: u64, // filenumber of active file
    files: HashMap<u64, FileMetadata>, //<filenumber, metadata>,
	file_positions: HashMap<u64, u64>,
	reader_cache: Cursor<Vec<u8>>, //cache which holds the current chunk content (for performance purposes)
	// this is also available via the ArcZffReaderMetadata, but this one is much more convenient to access. :)
	passive_object_filemetadata: HashMap<u64, Arc<HashMap<u64, FileMetadata>>>, //<object_number, <filenumber, Metadata>>,
}

impl<R: Read + Seek> ZffObjectReaderVirtual<R> {
    /// Initialize the [ZffObjectReaderLogical] with the recommended set of metadata which will be stored in memory.
	pub fn new(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Result<Self> {
			Self::with_obj_metadata(object_no, metadata)
	}

	/// Returns the [FileHeader] of the current active file
	pub fn current_fileheader(&self) -> Result<FileHeader> {
		let metadata = self.files
		.get(&self.active_file)
		.ok_or(ZffError::new(ZffErrorKind::Invalid, format!("{ERROR_MISSING_FILE_NUMBER}{}", self.active_file)))?;
		Ok(metadata.header.clone())
	}

	/// Returns the VFM for the given filenumber by reading them directly from segment.
	fn read_virtual_filemap(&self, filenumber: u64) -> Result<VirtualFileMap> {
		let filemetadata = self.filemetadata_by_filenumber(filenumber)?;
		if let Ok(VirtualFileContent::FileMapPosition(segment_no, offset)) = filemetadata.vffc() {
			let enc_info = EncryptionInformation::try_from(&self.object_header).ok();
			read_virtual_filemap_by_filemap_position(Arc::clone(&self.metadata), *segment_no, *offset, enc_info)
		} else {
			Err(ZffError::new(ZffErrorKind::Invalid, format!("{ERROR_ZFFREADER_MISSING_VFM}{filenumber}")))
		}
	}

	/// Initialze a single filemap (for internal use only - will be used for caching)
	fn initialize_filemap(&mut self, filenumber: u64) -> Result<()> {
		let vfm = self.read_virtual_filemap(filenumber)?;
		//already verified in self.read_virtual_filemap() that the type is VirtualFileContent::FileMapPosition
		let filemetadata = self.filemetadata_by_filenumber_mut(filenumber)?;
		if let FileFooterMetadata::VirtualFileFooterMetadata(ref mut vffm) = filemetadata.footer {
			vffm.vfc = VirtualFileContent::FileMap(vfm);
		}
		Ok(())
	}

	/// Pre-initializes all filemaps at cost of memory.
	pub fn initialize_filemaps(&mut self) -> Result<()> {
		let filenumbers = self.files.keys().cloned().collect::<Vec<u64>>();
		for filenumber in filenumbers {
			match self.initialize_filemap(filenumber) {
				Ok(_) => (),
				Err(e) => match e.kind() {
					ZffErrorKind::Invalid => (),
					_ => return Err(e),
				}
			}
		};
		Ok(())
	}
    
    /// creates a new [ZffObjectReaderVirtual] with the given metadata.
	fn with_obj_metadata(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Result<Self> {
        let object_header = metadata.object_header(&object_no).unwrap().clone();
		let object_footer = match metadata.object_footer(&object_no) {
			Some(ObjectFooter::Virtual(footer)) => footer.clone(),
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
			let header_offset = match object_footer.file_header_offsets.get(filenumber) {
				Some(offset) => offset,
				None => return Err(ZffError::new(ZffErrorKind::Invalid, ERROR_MALFORMED_SEGMENT)),
			};
			let (footer_segment_number, footer_offset) = match object_footer.file_footer_segment_numbers.get(filenumber) {
				None => return Err(ZffError::new(ZffErrorKind::Invalid, ERROR_MALFORMED_SEGMENT)),
				Some(segment_no) => match object_footer.file_footer_offsets.get(filenumber) {
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
			reader_cache: Cursor::new(Vec::new()),
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
		self.reader_cache.get_mut().clear();
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

	pub(crate) fn filemetadata_by_filenumber_mut(&mut self, filenumber: u64) -> Result<&mut FileMetadata> {
		match self.files.get_mut(&filenumber) {
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
		ObjectFooter::Virtual(self.object_footer.clone())
	}

	// Returns true if cache would filled, false if cache is empty (end of reader is reached).
	fn refill_reader_cache(&mut self) -> std::io::Result<bool> {
		let filemetadata = self.files.get(&self.active_file)
										  .ok_or(IoError::other(format!("{ERROR_MISSING_FILE_NUMBER}{}", self.active_file)))?;
		//unwrap is safe here: self.files and self.file_positions are both filled by new()-function.
		let absoulute_position_virtual_file = *self.file_positions.get(&self.active_file).unwrap();
		let vffm = match &filemetadata.footer {
			FileFooterMetadata::FileFooter(_) => return Err(IoError::other(ERROR_ZFFREADER_OPERATION)),
			FileFooterMetadata::VirtualFileFooterMetadata(metadata) => metadata,
		};
		let vfm = match vffm.vfc {
			VirtualFileContent::FileMap(ref vfm) => vfm,
			VirtualFileContent::FileMapPosition(segment_no, offset) => {
				&read_virtual_filemap_by_filemap_position(
					Arc::clone(&self.metadata), 
					segment_no, offset, 
					EncryptionInformation::try_from(&self.object_header).ok())?
			},
			_ => return Err(IoError::other(ERROR_ZFFREADER_OPERATION)),
		};
		let (offset_virtual_file, vfe) = floor_btree_entry(&vfm.extents,absoulute_position_virtual_file)
													               .ok_or(IoError::other(format!("{ERROR_ZFFREADER_MISSING_VALUE_VFM}{}", 
																   absoulute_position_virtual_file)))?;
		
		if absoulute_position_virtual_file >= offset_virtual_file + (vfe.length-1) {
			return Ok(false)
		}
		warn!("vfm: {vfm:?}");

		let relative_position_virtual_file = (absoulute_position_virtual_file - offset_virtual_file) as usize;
		
		let source_chunk_size = {
				let metadata_guard = self.metadata.object_metadata.read().unwrap();
				metadata_guard
				.get(&vfe.source_object_number)
				.ok_or(IoError::other(format!("{ERROR_ZFFREADER_MISSING_PASSIVE_OBJECT}{}", vfe.source_object_number)))?
				.header
				.chunk_size
		};
		let metadata_guard = self.metadata.object_metadata.read().unwrap();
		let obj_metadata = metadata_guard
														   .get(&vfe.source_object_number)
														   .ok_or(IoError::other(format!("{ERROR_ZFFREADER_MISSING_PASSIVE_OBJECT}{}", 
														   vfe.source_object_number)))?;
		let chunk_data = match &obj_metadata.footer {
			ObjectFooter::Physical(footer) => {
				let absolute_position_source_file = vfe.source_offset + relative_position_virtual_file as u64;
				let current_chunk_number = (footer.first_chunk_number * source_chunk_size + absolute_position_source_file) / source_chunk_size;
				if let Some(samebyte) = self.metadata.preloaded_chunkmaps.read().unwrap().get_samebyte(current_chunk_number) {
					vec![samebyte; source_chunk_size as usize]
				} else {
					let object_no = &vfe.source_object_number;
					get_chunk_data(object_no, Arc::clone(&self.metadata), current_chunk_number)?
				}
			},
			ObjectFooter::Logical(_) => {
				let source_filemetadata = self.passive_object_filemetadata
													.get(&vfe.source_object_number)
													.and_then(|files| files.get(&vfe.source_filenumber))
													.ok_or(IoError::other(format!("{ERROR_ZFFREADER_MISSING_PASSIVE_OBJECT}{}", vfe.source_object_number)))?;
				let first_chunk_number = source_filemetadata.first_chunk_number().ok_or(IoError::other(ERROR_MALFORMED_SEGMENT))?;

				let source_position_absolute = vfe.source_offset + relative_position_virtual_file as u64;
				let current_chunk_number = (first_chunk_number * source_chunk_size + source_position_absolute) / source_chunk_size;
				if let Some(samebyte) = self.metadata.preloaded_chunkmaps.read().unwrap().get_samebyte(current_chunk_number) {
					vec![samebyte; source_chunk_size as usize]
				} else {
					let object_no = &vfe.source_object_number;
					get_chunk_data(object_no, Arc::clone(&self.metadata), current_chunk_number)?
				}
			},
			_ => unimplemented!() //TODO
		};
		{
			self.reader_cache.set_position(0);
			let inner = self.reader_cache.get_mut();
			inner.clear();
			let source_inner_position = vfe.source_offset % source_chunk_size;
			let relative_end = vfe.length + source_inner_position;
			let slice_end = (relative_end.min(source_chunk_size) as usize);
			let chunk_position = source_inner_position as usize + relative_position_virtual_file;
			inner.extend_from_slice(&chunk_data[chunk_position..slice_end]);
		}
		Ok(true)
	}
}

/// Reads from current active file.
impl<R: Read + Seek> Read for ZffObjectReaderVirtual<R> {
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

/// Seeks in current active file.
impl<R: Read + Seek> Seek for ZffObjectReaderVirtual<R> {
    fn seek(&mut self, seek_from: SeekFrom) -> std::io::Result<u64> {
        let position = self.file_positions.get_mut(&self.active_file).ok_or(IoError::other(format!("{ERROR_MISSING_FILE_NUMBER}{}", self.active_file)))?;
		let filemetadata = self.files.get(&self.active_file).ok_or(IoError::other(format!("{ERROR_MISSING_FILE_NUMBER}{}", self.active_file)))?;
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
		self.reader_cache.get_mut().clear();
		Ok(*position)
    }
}

fn read_virtual_filemap_by_filemap_position<R: Read+Seek>(
	metadata: ArcZffReaderMetadata<R>,
		segment_no: u64, 
		offset: u64,
		enc_info: Option<EncryptionInformation>) -> Result<VirtualFileMap> {
	let vlfm = {
	let mut segments = metadata.segments.write().unwrap();
	match segments.get_mut(&segment_no) {
			None => return Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("{ERROR_MISSING_SEGMENT}{}", segment_no))),
			Some(segment) => {
				segment.seek(SeekFrom::Start(offset))?;
				//check encryption
				if let Some(enc_info) = &enc_info {
					VirtualFileMap::decode_encrypted_footer_with_key(segment, enc_info)?
				} else {
					VirtualFileMap::decode_directly(segment)?
				}
			}
		}
	};
	Ok(vlfm)
}