// - STD
use std::io::Cursor;
use std::collections::BTreeSet;


// - internal
use crate::{
	footer::{
		EncryptedObjectFooter, ObjectFooterLogical, ObjectFooterPhysical, ObjectFooterVirtual
	},
	header::{
		EncryptedObjectHeader, HashHeader, VirtualMappingInformation},
	helper::find_vmi_offset,
};

use super::*;

#[derive(Debug)]
pub(crate) struct ObjectMetadata {
	pub header: ObjectHeader,
	pub footer: ObjectFooter,
}

impl ObjectMetadata {
	pub(crate) fn new(header: ObjectHeader, footer: ObjectFooter) -> Self {
		Self { header, footer }
	}
}

/// An enum, which provides an appropriate object reader.
#[derive(Debug)]
pub(crate) enum ZffObjectReader<R: Read + Seek> {
	/// Contains a [ZffObjectReaderPhysical].
	Physical(Box<ZffObjectReaderPhysical<R>>),
	/// Contains a [ZffObjectReaderLogical].
	Logical(Box<ZffObjectReaderLogical<R>>),
	/// Contains a [ZffObjectReaderVirtual].
	Virtual(Box<ZffObjectReaderVirtual<R>>),
	/// Contains a [ZffObjectReaderEncrypted].
	Encrypted(Box<ZffObjectReaderEncrypted<R>>),
}

impl<R: Read + Seek> Read for ZffObjectReader<R> {
	fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
		match self {
			ZffObjectReader::Physical(reader) => reader.read(buf),
			ZffObjectReader::Logical(reader) => reader.read(buf),
			ZffObjectReader::Virtual(reader) => reader.read(buf),
  			ZffObjectReader::Encrypted(_) => Err(
				std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
		}
	}
}

impl<R: Read + Seek> Seek for ZffObjectReader<R> {
	fn seek(&mut self, seek_from: std::io::SeekFrom) -> std::result::Result<u64, std::io::Error> {
		match self {
			ZffObjectReader::Physical(reader) => reader.seek(seek_from),
			ZffObjectReader::Logical(reader) => reader.seek(seek_from),
			ZffObjectReader::Virtual(reader) => reader.seek(seek_from),
			ZffObjectReader::Encrypted(_) => Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
		}
	}
}

/// A reader which contains the appropriate metadata of a physical object 
/// (e.g. the appropriate [ObjectHeader](crate::header::ObjectHeader) and [ObjectFooter](crate::footer::ObjectFooter)).
#[derive(Debug)]
pub(crate) struct ZffObjectReaderPhysical<R: Read + Seek> {
	metadata: ArcZffReaderMetadata<R>,
	object_header: ObjectHeader,
	object_footer: ObjectFooterPhysical,
	position: u64
}

impl<R: Read + Seek> ZffObjectReaderPhysical<R> {
	/// creates a new [ZffObjectReaderPhysical] with the given metadata.
	pub fn with_metadata(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Self {
		let object_header = metadata.object_header(&object_no).unwrap().clone();
		let object_footer = match metadata.object_footer(&object_no) {
			Some(ObjectFooter::Physical(footer)) => footer.clone(),
			_ => unreachable!(), // already checked before in zffreader::initialize_unencrypted_object_reader();
		};
		Self {
			metadata,
			object_header,
  			object_footer,
			position: 0
		}
	}

	/// Returns a reference to the [ObjectHeader](crate::header::ObjectHeader).
	pub fn object_header_ref(&self) -> &ObjectHeader {
		&self.object_header
	}

	/// Returns the appropriate [ObjectFooter](crate::footer::ObjectFooter).
	pub fn object_footer(&self) -> ObjectFooter {
		ObjectFooter::Physical(self.object_footer.clone())
	}

	/// Returns the unwrapped object footer
	pub fn object_footer_unwrapped_ref(&self) -> &ObjectFooterPhysical {
		&self.object_footer
	}
}

impl<R: Read + Seek> Read for ZffObjectReaderPhysical<R> {
	fn read(&mut self, buffer: &mut [u8], ) -> std::io::Result<usize> {
		let chunk_size = self.object_header.chunk_size;
		let first_chunk_number = self.object_footer.first_chunk_number;
		let last_chunk_number = first_chunk_number + self.object_footer.number_of_chunks - 1;
		let mut current_chunk_number = (first_chunk_number * chunk_size + self.position) / chunk_size;
		let mut inner_position = (self.position % chunk_size) as usize; // the inner chunk position
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

		self.position += read_bytes as u64;
		Ok(read_bytes)
	}
}

impl<R: Read + Seek> Seek for ZffObjectReaderPhysical<R> {
	fn seek(&mut self, seek_from: SeekFrom) -> std::result::Result<u64, std::io::Error> {
		match seek_from {
			SeekFrom::Start(value) => {
				self.position = value;
			},
			SeekFrom::Current(value) => if self.position as i64 + value < 0 {
				return Err(std::io::Error::new(std::io::ErrorKind::Other, ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))
			} else if value >= 0 {
					self.position += value as u64;
			} else {
				self.position -= value as u64;
			},
			SeekFrom::End(value) => if self.position as i64 + value < 0 {
				return Err(std::io::Error::new(std::io::ErrorKind::Other, ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))
			} else if value >= 0 {
					self.position = self.object_footer.length_of_data + value as u64;
			} else {
				self.position = self.object_footer.length_of_data - value as u64;
			},
		}
		Ok(self.position)
	}
}

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

/// A reader which contains the appropriate metadata of the virtual object 
/// (e.g. the appropriate [ObjectHeader](crate::header::ObjectHeader) and [ObjectFooter](crate::footer::ObjectFooter)).
#[derive(Debug)]
pub(crate) struct ZffObjectReaderVirtual<R: Read + Seek> {
	metadata: ArcZffReaderMetadata<R>,
	/// Contains the appropriate object header
	object_header: ObjectHeader,
	/// Contains the appropriate object footer of the virtual object
	object_footer: ObjectFooterVirtual,
	/// The virtual object map
	virtual_object_map: BTreeSet<BTreeMap<u64, (u64, u64)>>, 
	/// the internal reader position
	position: u64,
}

impl<R: Read + Seek> ZffObjectReaderVirtual<R> {
	/// creates a new [ZffObjectReaderVirtual] with the given metadata.
	pub fn with_data(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Self {
		let object_header = metadata.object_header(&object_no).unwrap().clone();
		let object_footer = match metadata.object_footer(&object_no) {
			Some(ObjectFooter::Virtual(footer)) => footer.clone(),
			_ => unreachable!(), // already checked before in zffreader::initialize_unencrypted_object_reader();
		};
		Self {
			metadata,
			object_header,
			object_footer,
			virtual_object_map: BTreeSet::new(), //TODO: Fill this map with the appropriate data :D !!!
			position: 0,
		}
	}

	/// Returns a reference of the appropriate [ObjectHeader](crate::header::ObjectHeader).
	pub fn object_header_ref(&self) -> &ObjectHeader {
		&self.object_header
	}

	/// Returns a reference of the appropriate [crate::footer::ObjectFooterVirtual].
	pub fn object_footer_unwrapped_ref(&self) -> &ObjectFooterVirtual {
		&self.object_footer
	}

	/// Returns the appropriate [ObjectFooter](crate::footer::ObjectFooter).
	pub fn object_footer(&self) -> ObjectFooter {
		ObjectFooter::Virtual(self.object_footer.clone())
	}

	/// fills the internal virtual_object_map with the given data.
	pub fn fill_object_map(&mut self, virtual_object_map: BTreeSet<BTreeMap<u64, (u64, u64)>>) {
		self.virtual_object_map = virtual_object_map;
	}
}

impl<R: Read + Seek> Read for ZffObjectReaderVirtual<R> {
	fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
		let mut read_bytes = 0; // number of bytes which are written to buffer
		
		'outer: loop {
			// find the appropriate mapping information.
			let virtual_mapping_information = match get_vmi_info(
				&self.virtual_object_map, 
				self.position, 
				Arc::clone(&self.metadata)) {
				Ok(mi) => mi,
				Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
			};

			let vmi_obj_no = virtual_mapping_information.object_number;
			let chunk_size = match self.metadata.object_metadata.read().unwrap().get(&vmi_obj_no) {
				Some(ref obj) => obj.header.chunk_size,
				None => return Err(std::io::Error::new(
					std::io::ErrorKind::Other, 
					format!("{ERROR_MISSING_OBJECT_HEADER_IN_SEGMENT}{vmi_obj_no}"))),
			};
			let mut current_chunk_number = virtual_mapping_information.start_chunk_no;
			let mut inner_position = virtual_mapping_information.chunk_offset as usize; // the inner chunk position
			let mut remaining_offset_length = virtual_mapping_information.length as usize;

			loop {
				if read_bytes == buffer.len() {
					break 'outer;
				}

				let chunk_data = if let Some(samebyte) = self.metadata.preloaded_chunkmaps.read().unwrap().get_samebyte(current_chunk_number) {
					vec![samebyte; chunk_size as usize]
				} else {
					let object_no = &self.object_header.object_number;
					get_chunk_data(object_no, Arc::clone(&self.metadata), current_chunk_number)?
				};

				let mut should_break = false;
				let mut cursor = if remaining_offset_length as u64 > chunk_data[inner_position..].len() as u64 {
					Cursor::new(&chunk_data[inner_position..])
				} else {
					should_break = true;
					Cursor::new(&chunk_data[inner_position..remaining_offset_length])
				};
				let read_bytes_at_round = cursor.read(&mut buffer[read_bytes..])?;
				read_bytes += read_bytes_at_round;
				remaining_offset_length -= read_bytes_at_round;
				if should_break {
					break;
				}
				inner_position = 0;
				current_chunk_number += 1;
			}

		}

		self.position += read_bytes as u64;
		Ok(read_bytes)
	}
}

fn get_vmi_info<R: Read + Seek>(
	vmi_map: &BTreeSet<BTreeMap<u64, (u64, u64)>>, 
	offset: u64,
	metadata: ArcZffReaderMetadata<R>) -> Result<VirtualMappingInformation> {
    let (segment_no, offset) = find_vmi_offset(vmi_map, offset).ok_or_else(|| ZffError::new(ZffErrorKind::NotFound, "VMI not found"))?;
    let mut segments = metadata.segments.write().unwrap();
	let segment = match segments.get_mut(&segment_no) {
		Some(segment) => segment,
		None => return Err(ZffError::new(
			ZffErrorKind::Missing, 
			ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
	};
	segment.seek(SeekFrom::Start(offset))?;
	VirtualMappingInformation::decode_directly(segment)
}

impl<R: Read + Seek> Seek for ZffObjectReaderVirtual<R> {
	fn seek(&mut self, seek_from: SeekFrom) -> std::result::Result<u64, std::io::Error> {
		match seek_from {
			SeekFrom::Start(value) => {
				self.position = value;
			},
			SeekFrom::Current(value) => if self.position as i64 + value < 0 {
				return Err(std::io::Error::new(std::io::ErrorKind::Other, ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))
			} else if value >= 0 {
					self.position += value as u64;
			} else {
				self.position -= value as u64;
			},
			SeekFrom::End(value) => if self.position as i64 + value < 0 {
				return Err(std::io::Error::new(std::io::ErrorKind::Other, ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))
			} else if value >= 0 {
					self.position = self.object_footer.length_of_data + value as u64;
			} else {
				self.position = self.object_footer.length_of_data - value as u64;
			},
		}
		Ok(self.position)
	}
}

/// A reader which contains the appropriate metadata of a encrypted object 
/// (e.g. the appropriate [ObjectHeader](crate::header::ObjectHeader) and [ObjectFooter](crate::footer::ObjectFooter)).
#[derive(Debug)]
pub(crate) struct ZffObjectReaderEncrypted<R: Read + Seek> {
	encrypted_header: EncryptedObjectHeader,
	encrypted_footer: EncryptedObjectFooter,
	metadata: ArcZffReaderMetadata<R>,
}

impl<R: Read + Seek> ZffObjectReaderEncrypted<R> {
	/// creates a new [ZffObjectReaderEncrypted] with the given metadata.
	pub fn with_data(
		encrypted_header: EncryptedObjectHeader, 
		encrypted_footer: EncryptedObjectFooter, 
		metadata: ArcZffReaderMetadata<R>) -> Self {
		Self {
			encrypted_header,
			encrypted_footer,
			metadata,
		}
	}

	/// Tries to decrypt the [ZffObjectReader] with the given parameters.
	pub fn decrypt_with_password<P>(&mut self, password: P) -> Result<ZffObjectReader<R>> 
	where
		P: AsRef<[u8]>,
		R: Read + Seek,
	{
		let decrypted_object_header = self.encrypted_header.decrypt_with_password(password)?;
		let enc_info = EncryptionInformation::try_from(&decrypted_object_header)?;
		let decrypted_footer = self.encrypted_footer.decrypt(enc_info.encryption_key, enc_info.algorithm)?;

		let obj_no = decrypted_object_header.object_number;
		let obj_metadata = ObjectMetadata::new(decrypted_object_header, decrypted_footer.clone());
		self.metadata.object_metadata.write().unwrap().insert(obj_no, obj_metadata);

		let obj_reader = match decrypted_footer {
			ObjectFooter::Physical(_) => ZffObjectReader::Physical(Box::new(
				ZffObjectReaderPhysical::with_metadata(
					obj_no, 
					Arc::clone(&self.metadata)))),
			ObjectFooter::Logical(_) => ZffObjectReader::Logical(Box::new(
				ZffObjectReaderLogical::with_obj_metadata_recommended(
					obj_no, 
					Arc::clone(&self.metadata))?)),
			ObjectFooter::Virtual(_) => ZffObjectReader::Virtual(Box::new(
				ZffObjectReaderVirtual::with_data(
					obj_no, 
					Arc::clone(&self.metadata)))),
		};

		Ok(obj_reader)

	}
}

/// The Metadata of a [File](crate::file::File).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FileMetadata {
	/// The file number of the parent directory (0 if the parent directory is the root directory).
	pub parent_file_number: u64,
	/// The length of the file in bytes.
	pub length_of_data: u64,
	/// The first chunk number used by this file.
	pub first_chunk_number: u64,
	/// The number of all chunks which are used for this file.
	pub number_of_chunks: u64,
	/// Position of the internal reader. This is mostly internally used.
	pub position: u64,
	/// The appropriate type of the file.
	pub file_type: FileType,
	/// The appropriate filename.
	pub filename: Option<String>,
	/// The metadata of the appropriate file.
	pub metadata_ext: HashMap<String, MetadataExtendedValue>,
	/// The timestamp when the acquisition has started.
	pub acquisition_start: Option<u64>,
	/// The timestamp when the acquisition has ended.
	pub acquisition_end: Option<u64>,
	/// The appropriate hash header of the file. 
	pub hash_header: Option<HashHeader>,
}

impl FileMetadata {
	/// Creates the [FileMetadata] with minimum amount of data. Most optional fields will be "None" and have to
	/// read directly from zff container.
	/// This Method will reduce the memory usage in the most possible way.
	/// This Option will provide:  
	/// - the parent file number
	/// - the length (or size) of the file
	/// - the first chunk number
	/// - the number of chunks
	/// - the internally used reader position
	/// - the filetype
	pub fn with_header_minimal(fileheader: &FileHeader, filefooter: &FileFooter) -> Self {
		Self {
			parent_file_number: fileheader.parent_file_number,
			length_of_data: filefooter.length_of_data,
			first_chunk_number: filefooter.first_chunk_number,
			number_of_chunks: filefooter.number_of_chunks,
			position: 0,
			file_type: fileheader.file_type.clone(),
			filename: None,
			metadata_ext: HashMap::new(),
			acquisition_start: None,
			acquisition_end: None,
			hash_header: None,
		}
	}

	/// Creates the [FileMetadata] with recommended amount of data. Most optional fields will be "None" and have to
	/// read directly from zff container.
	/// This Method will reduce the memory usage a bit.
	/// This Option will provide:  
	/// - the parent file number
	/// - the length (or size) of the file
	/// - the first chunk number
	/// - the number of chunks
	/// - the internally used reader position
	/// - the filetype
	/// - the filename
	/// - the metadata of the file
	pub fn with_header_recommended(fileheader: &FileHeader, filefooter: &FileFooter) -> Self {
		Self {
			parent_file_number: fileheader.parent_file_number,
			length_of_data: filefooter.length_of_data,
			first_chunk_number: filefooter.first_chunk_number,
			number_of_chunks: filefooter.number_of_chunks,
			position: 0,
			file_type: fileheader.file_type.clone(),
			filename: Some(fileheader.filename.clone()),
			metadata_ext: extract_recommended_metadata(fileheader),
			acquisition_start: None,
			acquisition_end: None,
			hash_header: None,
		}
	}

	/// Creates the [FileMetadata] with recommended amount of data. Most optional fields will be "None" and have to
	/// read directly from zff container.
	/// This Method will reduce the need of I/O access in the most possible way.
	/// This Option will provide:  
	/// - the parent file number
	/// - the length (or size) of the file
	/// - the first chunk number
	/// - the number of chunks
	/// - the internally used reader position
	/// - the filetype
	/// - the filename
	/// - the metadata of the file
	/// - the timestamps of start and end of the acquisition
	/// - the appropriate hash header
	pub fn with_header_all(fileheader: &FileHeader, filefooter: &FileFooter) -> Self {
		Self {
			parent_file_number: fileheader.parent_file_number,
			length_of_data: filefooter.length_of_data,
			first_chunk_number: filefooter.first_chunk_number,
			number_of_chunks: filefooter.number_of_chunks,
			position: 0,
			file_type: fileheader.file_type.clone(),
			filename: Some(fileheader.filename.clone()),
			metadata_ext: extract_all_metadata(fileheader),
			acquisition_start: Some(filefooter.acquisition_start),
			acquisition_end: Some(filefooter.acquisition_end),
			hash_header: Some(filefooter.hash_header.clone()),
		}
	}
}

#[derive(Debug)]
enum PreloadDegree {
	//Minimal,
	Recommended,
	//All,
}