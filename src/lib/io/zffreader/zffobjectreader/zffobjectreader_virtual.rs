// - STD
use std::collections::{HashMap};
use std::io::{Error as IoError, ErrorKind as IoEKind, Read, Seek, SeekFrom};
use std::sync::{Arc};

// - internal
use crate::prelude::*;
use crate::{
	FileFooterMetadata,
	FileMetadata,
	helper::floor_btree_entry,
	io::zffreader::{
		ArcZffReaderMetadata,
		get_chunk_data,
	},
	VirtualFileContent,
};

// - external
use moka::sync::Cache as MokaCache;

/// A reader which contains the appropriate metadata of a logical object 
/// (e.g. the appropriate [ObjectHeader](crate::header::ObjectHeader) and [ObjectFooter](crate::footer::ObjectFooter)).
#[derive(Debug)]
pub(crate) struct ZffObjectReaderVirtual<R: ReadAt> {
	metadata: ArcZffReaderMetadata<R>,
	object_header: ObjectHeader,
	object_footer: ObjectFooterVirtual,
    active_file: u64, // filenumber of active file
    files: HashMap<u64, FileMetadata>, //<filenumber, metadata>,
	file_positions: HashMap<u64, u64>,
	reader_cache: MokaCache<u64, Arc<ChunkContent>>, //cache which holds the current chunk content (for performance purposes)
	// this is also available via the ArcZffReaderMetadata, but this one is much more convenient to access. :)
	passive_object_filemetadata: HashMap<u64, Arc<HashMap<u64, FileMetadata>>>, //<object_number, <filenumber, Metadata>>,
}

impl<R: ReadAt> ZffObjectReaderVirtual<R> {
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
			let obj_metadata = match metadata.object_metadata.get(passive_object_number) {
				Some(obj_metadata) => obj_metadata.get(),
				None => return Err(ZffError::new(
					ZffErrorKind::Missing, 
					format!("{ERROR_ZFFREADER_MISSING_PASSIVE_OBJECT}{passive_object_number}"))),
			};
			let obj_metadata = obj_metadata
			.ok_or(ZffError::new(ZffErrorKind::Missing, format!("{ERROR_ZFFREADER_MISSING_PASSIVE_OBJECT}{passive_object_number}")))?;
		
			let files = match obj_metadata.files.get() {
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
			let fileheader = match metadata.segments.get(header_segment_number) {
				None => return Err(ZffError::new(
					ZffErrorKind::Missing, 
					format!("{ERROR_MISSING_SEGMENT}{header_segment_number}"))),
				Some(segment) => {
					//check encryption
					if let Some(enc_info) = &enc_info {
						FileHeader::decode_at_encrypted_header_with_key(segment, *header_offset, enc_info)?
					} else {
						FileHeader::decode_at(segment, *header_offset)?
					}
				}
			};
			let filefooter = match metadata.segments.get(footer_segment_number) {
				None => return Err(ZffError::new(
					ZffErrorKind::Missing, 
					format!("{ERROR_MISSING_SEGMENT}{footer_segment_number}"))),
				Some(segment) => {
					//check encryption
					if let Some(enc_info) = &enc_info {
						VirtualFileFooter::decode_at_encrypted_footer_with_key(segment, *footer_offset, enc_info)?
					} else {
						VirtualFileFooter::decode_at(segment, *footer_offset)?
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
			reader_cache: MokaCache::builder().max_capacity(DEFAULT_CHUNK_CACHE_CAPACITY).build(),
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
	pub(crate) fn current_filemetadata(&self) -> Result<&FileMetadata> {
		self.filemetadata_by_filenumber(self.active_file)
	}

	/// Returns the [FileMetadata] for the given filenumber.
	/// # Error
	/// Fails if file not exists in object.
	pub(crate) fn filemetadata_by_filenumber(&self, file_number: u64) -> Result<&FileMetadata> {
		match self.files.get(&file_number) {
			Some(metadata) => Ok(metadata),
			None => Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("(filemetadata) {ERROR_MISSING_FILE_NUMBER}{}", self.active_file)))
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

	fn cached_chunk(&self, object_number: &u64, chunk_number: u64) -> std::io::Result<Arc<ChunkContent>> {
		if let Some(chunk_content) = self.reader_cache.get(&chunk_number) {
			return Ok(chunk_content);
		}

		let chunk_content = if let Some(samebyte) =
			self.metadata.preloaded_chunkmaps.read().unwrap().get_samebyte(chunk_number)
		{
			Arc::new(ChunkContent::SameBytes(samebyte))
		} else {
			Arc::new(get_chunk_data(object_number, Arc::clone(&self.metadata), chunk_number)?)
		};

		self.reader_cache.insert(chunk_number, Arc::clone(&chunk_content));
		Ok(chunk_content)
	}

	pub fn read_at_file(&self, buf: &mut [u8], offset: u64, file_no: u64) -> std::io::Result<usize> {
		let filemetadata = self.files
			.get(&file_no)
			.ok_or(IoError::other(format!("{ERROR_MISSING_FILE_NUMBER}{file_no}")))?;

		if buf.is_empty() || offset >= filemetadata.length_of_data() {
			return Ok(0);
		}

		let vffm = match &filemetadata.footer {
			FileFooterMetadata::VirtualFileFooterMetadata(metadata) => metadata,
			FileFooterMetadata::FileFooter(_) => return Err(IoError::other(ERROR_ZFFREADER_OPERATION)),
		};

		// used an explicit buffer to avoid Rust lifetime issues.
		let vfm_buffer;
		let vfm = match vffm.vfc {
			VirtualFileContent::FileMap(ref vfm) => vfm,
			VirtualFileContent::FileMapPosition(segment_no, offset) => {
				vfm_buffer = read_virtual_filemap_by_filemap_position(
					Arc::clone(&self.metadata),
					segment_no,
					offset,
					EncryptionInformation::try_from(&self.object_header).ok(),
				)?;
				&vfm_buffer
			},
			_ => return Err(IoError::other(ERROR_ZFFREADER_OPERATION)),
		};

		let bytes_to_read = (buf.len() as u64).min(filemetadata.length_of_data() - offset) as usize;
		let mut read_bytes = 0;

		while read_bytes < bytes_to_read {
			let virtual_pos = offset + read_bytes as u64;
			let (extent_offset, vfe) = floor_btree_entry(&vfm.extents, virtual_pos)
				.ok_or(IoError::other(format!("{ERROR_ZFFREADER_MISSING_VALUE_VFM}{virtual_pos}")))?;

			if virtual_pos >= extent_offset + vfe.length {
				return Err(IoError::other(format!("{ERROR_ZFFREADER_MISSING_VALUE_VFM}{virtual_pos}")));
			}

			let relative_in_extent = virtual_pos - extent_offset;
			let source_pos = vfe.source_offset + relative_in_extent;

			let obj_metadata = self.metadata.object_metadata
				.get(&vfe.source_object_number)
				.ok_or(IoError::other(format!("{ERROR_ZFFREADER_MISSING_PASSIVE_OBJECT}{}", vfe.source_object_number)))?
				.get()
				.ok_or(IoError::other(format!("{ERROR_ZFFREADER_MISSING_PASSIVE_OBJECT}{}", vfe.source_object_number)))?;

			let source_chunk_size = obj_metadata.header.chunk_size;
			if source_chunk_size == 0 {
				return Err(IoError::new(IoEKind::InvalidData, ERROR_MALFORMED_SEGMENT));
			}

			let current_chunk_number = match &obj_metadata.footer {
				ObjectFooter::Physical(footer) => {
					footer.first_chunk_number + source_pos / source_chunk_size
				},
				ObjectFooter::Logical(_) => {
					let source_filemetadata = self.passive_object_filemetadata
						.get(&vfe.source_object_number)
						.and_then(|files| files.get(&vfe.source_filenumber))
						.ok_or(IoError::other(format!("{ERROR_ZFFREADER_MISSING_PASSIVE_OBJECT}{}", vfe.source_object_number)))?;

					source_filemetadata
						.first_chunk_number()
						.ok_or(IoError::other(ERROR_MALFORMED_SEGMENT))?
						+ source_pos / source_chunk_size
				},
				_ => unimplemented!(),
			};

			let source_inner_pos = (source_pos % source_chunk_size) as usize;
			let current_read_len = (source_chunk_size as usize - source_inner_pos)
				.min((vfe.length - relative_in_extent) as usize)
				.min(bytes_to_read - read_bytes);

			let chunk_content = self.cached_chunk(&vfe.source_object_number, current_chunk_number)?;

			match chunk_content.as_ref() {
				ChunkContent::Raw(data) => {
					let end = source_inner_pos + current_read_len;
					let chunk_slice = data.get(source_inner_pos..end)
						.ok_or(IoError::new(IoEKind::UnexpectedEof, ERROR_MALFORMED_SEGMENT))?;
					buf[read_bytes..read_bytes + current_read_len].copy_from_slice(chunk_slice);
				},
				ChunkContent::SameBytes(byte) => {
					buf[read_bytes..read_bytes + current_read_len].fill(*byte);
				},
				ChunkContent::Duplicate(_) => unreachable!(),
			}

			read_bytes += current_read_len;
		}

		Ok(read_bytes)
	}

	pub fn read_at_file_to_end(&self, buf: &mut Vec<u8>, mut offset: u64, file_no: u64) -> std::io::Result<usize> {
		let start_offset = offset;
        let mut chunk = [0u8; 8192]; //TODO: move "hardcoded" size to constants.rs
        loop {
            match self.read_at_file(&mut chunk, offset, file_no) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    offset += n as u64;
                }
                Err(e) if e.kind() == IoEKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        Ok((offset-start_offset) as usize)
	}
}

impl<R: ReadAt> ReadAt for ZffObjectReaderVirtual<R> {
	fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
		self.read_at_file(buf, offset, self.active_file)
	}

	fn size(&mut self) -> std::io::Result<u64> {
		let filemetadata = self.files
			.get(&self.active_file)
			.ok_or(IoError::other(format!("{ERROR_MISSING_FILE_NUMBER}{}", self.active_file)))?;
		Ok(filemetadata.length_of_data())
	}
}

impl<R: ReadAt> Read for ZffObjectReaderVirtual<R> {
	fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
		let afp = match self.file_positions.get(&self.active_file) {
			Some(afp) => afp,
			None => return Err(IoError::new(IoEKind::NotFound, format!("{ERROR_MISSING_FILE_NUMBER}{}", &self.active_file))),
		};
		let read_bytes = self.read_at(buffer, *afp)?;
		let afp = match self.file_positions.get_mut(&self.active_file) {
			Some(afp) => afp,
			None => return Err(IoError::new(IoEKind::NotFound, format!("{ERROR_MISSING_FILE_NUMBER}{}", &self.active_file))),
		};
		*afp += read_bytes as u64;
		Ok(read_bytes)
	}
}

impl<R: ReadAt> Seek for ZffObjectReaderVirtual<R> {
	fn seek(&mut self, seek_from: SeekFrom) -> std::result::Result<u64, std::io::Error> {
		let afp = match self.file_positions.get_mut(&self.active_file) {
			Some(afp) => afp,
			None => return Err(IoError::new(IoEKind::NotFound, format!("{ERROR_MISSING_FILE_NUMBER}{}", &self.active_file))),
		};
		let filemetadata = self.files.get(&self.active_file).ok_or(IoError::other(format!("{ERROR_MISSING_FILE_NUMBER}{}", self.active_file)))?;
		let length_of_data = filemetadata.length_of_data();
		*afp = match seek_from {
			SeekFrom::Start(value) => value,
			SeekFrom::Current(value) => afp.checked_add_signed(value).ok_or_else(|| {
				std::io::Error::other(ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION)
			})?,
			SeekFrom::End(value) => length_of_data.checked_add_signed(value).ok_or_else(|| {
				std::io::Error::other(ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION)
			})?,
		};
		Ok(*afp)
	}
}

fn read_virtual_filemap_by_filemap_position<R: ReadAt>(
	metadata: ArcZffReaderMetadata<R>,
		segment_no: u64, 
		offset: u64,
		enc_info: Option<EncryptionInformation>) -> Result<VirtualFileMap> {
	let vlfm = {
	match metadata.segments.get(&segment_no) {
			None => return Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("{ERROR_MISSING_SEGMENT}{}", segment_no))),
			Some(segment) => {
				//check encryption
				if let Some(enc_info) = &enc_info {
					VirtualFileMap::decode_at_encrypted_footer_with_key(segment, offset, enc_info)?
				} else {
					VirtualFileMap::decode_at(segment, offset)?
				}
			}
		}
	};
	Ok(vlfm)
}