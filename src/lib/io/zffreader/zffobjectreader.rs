// - STD
use std::io::Cursor;
use std::collections::BTreeSet;


// - internal
use crate::{
	footer::{
		ObjectFooterPhysical,
		ObjectFooterLogical,
		ObjectFooterVirtual,
		EncryptedObjectFooter,
	},
	header::{
		HashHeader, 
		EncryptedObjectHeader, 
		VirtualMappingInformation},
	helper::find_vmi_offset,
};

use super::*;

/// An enum, which provides an appropriate object reader.
#[derive(Debug)]
pub enum ZffObjectReader {
	/// Contains a [ZffObjectReaderPhysical].
	Physical(Box<ZffObjectReaderPhysical>),
	/// Contains a [ZffObjectReaderLogical].
	Logical(Box<ZffObjectReaderLogical>),
	/// Contains a [ZffObjectReaderVirtual].
	Virtual(Box<ZffObjectReaderVirtual>),
	/// Contains a [ZffObjectReaderEncrypted].
	Encrypted(Box<ZffObjectReaderEncrypted>),
}

impl Seek for ZffObjectReader {
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
pub struct ZffObjectReaderPhysical {
	object_header: ObjectHeader,
	object_footer: ObjectFooterPhysical,
	position: u64
}

impl ZffObjectReaderPhysical {
	/// creates a new [ZffObjectReaderPhysical] with the given metadata.
	pub fn with_obj_metadata(
		object_header: ObjectHeader, 
		object_footer: ObjectFooterPhysical,
		) -> Self {
		Self {
			object_header,
			object_footer,
			position: 0
		}
	}

	/// Returns a reference of the appropriate [ObjectHeader](crate::header::ObjectHeader).
	pub fn object_header_ref(&self) -> &ObjectHeader {
		&self.object_header
	}

	/// Returns the appropriate [ObjectFooter](crate::footer::ObjectFooter).
	pub fn object_footer(&self) -> ObjectFooter {
		ObjectFooter::Physical(self.object_footer.clone())
	}

	/// Works like [std::io::Read] for the underlying data, but needs also the segments and the optional preloaded chunkmap.  
	pub fn read_with_segments<R: Read + Seek>(
		&mut self, 
		buffer: &mut [u8], 
		segments: &mut HashMap<u64, Segment<R>>,
		preloaded_chunkmap: &PreloadedChunkMap,
		global_chunkmap: &BTreeMap<u64, u64>,
		) -> std::result::Result<usize, std::io::Error> {
		let chunk_size = self.object_header.chunk_size;
		let first_chunk_number = self.object_footer.first_chunk_number;
		let last_chunk_number = first_chunk_number + self.object_footer.number_of_chunks - 1;
		let mut current_chunk_number = (first_chunk_number * chunk_size + self.position) / chunk_size;
		let mut inner_position = (self.position % chunk_size) as usize; // the inner chunk position
		let mut read_bytes = 0; // number of bytes which are written to buffer
		let compression_algorithm = &self.object_header.compression_header.algorithm;

		loop {
			if read_bytes == buffer.len() || current_chunk_number > last_chunk_number {
				break;
			}
			let segment = match get_segment_of_chunk_no(current_chunk_number, global_chunkmap) {
				Some(segment_no) => match segments.get_mut(&segment_no) {
					Some(segment) => segment,
					None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
				},
				None => break,
			};
			let enc_information = EncryptionInformation::try_from(&self.object_header).ok();
			let chunk_data = get_chunk_data(
				segment, 
				current_chunk_number, 
				&enc_information, 
				compression_algorithm, 
				chunk_size,
				extract_offset_from_preloaded_chunkmap(preloaded_chunkmap, current_chunk_number))?;
			let mut cursor = Cursor::new(&chunk_data[inner_position..]);
			read_bytes += cursor.read(&mut buffer[read_bytes..])?;
			inner_position = 0;
			current_chunk_number += 1;
		}

		self.position += read_bytes as u64;
		Ok(read_bytes)
	}
}

impl Seek for ZffObjectReaderPhysical {
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
pub struct ZffObjectReaderLogical {
	object_header: ObjectHeader,
	object_footer: ObjectFooterLogical,
	active_file: u64, // filenumber of active file
	files: HashMap<u64, FileMetadata>//<filenumber, metadata>
}

impl ZffObjectReaderLogical {
	/// Initialize the [ZffObjectReaderLogical] with a minimal set of (the absolutly required) metadata which will be stored in memory.
	pub fn with_obj_metadata_minimal<R: Read + Seek>(
		object_header: ObjectHeader, 
		object_footer: ObjectFooterLogical,
		segments: &mut HashMap<u64, Segment<R>>, //<segment number, Segment-object>
		) -> Result<Self> {
		Self::with_obj_metadata(object_header, object_footer, segments, PreloadDegree::Minimal)
	}

	/// Initialize the [ZffObjectReaderLogical] with the recommended set of metadata which will be stored in memory.
	pub fn with_obj_metadata_recommended<R: Read + Seek>(
		object_header: ObjectHeader, 
		object_footer: ObjectFooterLogical,
		segments: &mut HashMap<u64, Segment<R>>, //<segment number, Segment-object>
		) -> Result<Self> {
		Self::with_obj_metadata(object_header, object_footer, segments, PreloadDegree::Recommended)
	}

	/// Initialize the [ZffObjectReaderLogical] which will store all metadata in memory.
	pub fn with_obj_metadata_all<R: Read + Seek>(
		object_header: ObjectHeader, 
		object_footer: ObjectFooterLogical,
		segments: &mut HashMap<u64, Segment<R>>, //<segment number, Segment-object>
		) -> Result<Self> {
		Self::with_obj_metadata(object_header, object_footer, segments, PreloadDegree::All)
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
	pub fn current_fileheader<R: Read + Seek>(&self, segments: &mut HashMap<u64, Segment<R>>) -> Result<FileHeader> {
		let header_segment_number = match self.object_footer.file_header_segment_numbers().get(&self.active_file) {
			Some(no) => no,
			None => return Err(ZffError::new(ZffErrorKind::MissingFileNumber, self.active_file.to_string()))
		};
		let header_offset = match self.object_footer.file_header_offsets().get(&self.active_file) {
			Some(offset) => offset,
			None => return Err(ZffError::new(ZffErrorKind::MalformedSegment, "")),
		};
		let enc_info = if let Some(encryption_header) = &self.object_header.encryption_header {
			let key = match encryption_header.get_encryption_key() {
				Some(key) => key,
				None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, "")),
			};
			Some(EncryptionInformation::new(key, encryption_header.algorithm.clone()))
		} else {
			None
		};
		match segments.get_mut(header_segment_number) {
			None => Err(ZffError::new(ZffErrorKind::MissingSegment, "")),
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
	pub fn current_filefooter<R: Read + Seek>(&self, segments: &mut HashMap<u64, Segment<R>>) -> Result<FileFooter> {
		let footer_segment_number = match self.object_footer.file_footer_segment_numbers().get(&self.active_file) {
			Some(no) => no,
			None => return Err(ZffError::new(ZffErrorKind::MissingFileNumber, self.active_file.to_string()))
		};
		let footer_offset = match self.object_footer.file_footer_offsets().get(&self.active_file) {
			Some(offset) => offset,
			None => return Err(ZffError::new(ZffErrorKind::MalformedSegment, "")),
		};
		let enc_info = if let Some(encryption_header) = &self.object_header.encryption_header {
			let key = match encryption_header.get_encryption_key() {
				Some(key) => key,
				None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, "")),
			};
			Some(EncryptionInformation::new(key, encryption_header.algorithm.clone()))
		} else {
			None
		};
		match segments.get_mut(footer_segment_number) {
			None => Err(ZffError::new(ZffErrorKind::MissingSegment, "")),
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

	fn with_obj_metadata<R: Read + Seek>(
		object_header: ObjectHeader, 
		object_footer: ObjectFooterLogical,
		segments: &mut HashMap<u64, Segment<R>>, //<segment number, Segment-object>
		degree_value: PreloadDegree,
		) -> Result<Self> {
		#[cfg(feature = "log")]
		debug!("Initialize logical object {}", object_header.object_number);

		let enc_info = if let Some(encryption_header) = &object_header.encryption_header {
			let key = match encryption_header.get_encryption_key() {
				Some(key) => key,
				None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, "")),
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
				None => return Err(ZffError::new(ZffErrorKind::MalformedSegment, "")),
			};
			let (footer_segment_number, footer_offset) = match object_footer.file_footer_segment_numbers().get(filenumber) {
				None => return Err(ZffError::new(ZffErrorKind::MalformedSegment, "")),
				Some(segment_no) => match object_footer.file_footer_offsets().get(filenumber) {
					None => return Err(ZffError::new(ZffErrorKind::MalformedSegment, "")),
					Some(offset) => (segment_no, offset),
				}
			};

			let fileheader = match segments.get_mut(header_segment_number) {
				None => return Err(ZffError::new(ZffErrorKind::MissingSegment, "")),
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
				None => return Err(ZffError::new(ZffErrorKind::MissingSegment, "")),
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
				PreloadDegree::Minimal => FileMetadata::with_header_minimal(&fileheader, &filefooter),
				PreloadDegree::Recommended => FileMetadata::with_header_recommended(&fileheader, &filefooter),
				PreloadDegree::All => FileMetadata::with_header_all(&fileheader, &filefooter),
			};
			files.insert(*filenumber, metadata);
		}

		#[cfg(feature = "log")]
		debug!("{} files were successfully initialized for logical object {}.", files.len(), object_header.object_number);

		Ok(Self {
			object_header,
			object_footer,
			active_file: 1,
			files,
		})
	}

	/// Sets the file of the appropriate filenumber active.
	/// # Error
	/// fails if no appropriate file for the given filenumber exists.
	pub fn set_active_file(&mut self, filenumber: u64) -> Result<()> {
		match self.files.get(&filenumber) {
			Some(_) => self.active_file = filenumber,
			None => return Err(ZffError::new(ZffErrorKind::MissingFileNumber, filenumber.to_string()))
		}
		Ok(())
	}

	/// Returns the [FileMetadata] of the active file.
	/// # Error
	/// Fails if no valid file is set as the active one.
	pub(crate) fn filemetadata(&self) -> Result<&FileMetadata> {
		match self.files.get(&self.active_file) {
			Some(metadata) => Ok(metadata),
			None => Err(ZffError::new(ZffErrorKind::MissingFileNumber, self.active_file.to_string()))
		}
	}

	/// Works like [std::io::Read] for the underlying data, but needs also the segments and the optional preloaded chunkmap.
	pub fn read_with_segments<R: Read + Seek>(
		&mut self, 
		buffer: &mut [u8], 
		segments: &mut HashMap<u64, Segment<R>>,
		preloaded_chunkmap: &PreloadedChunkMap,
		global_chunkmap: &BTreeMap<u64, u64>,
		) -> std::result::Result<usize, std::io::Error> {
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
		let compression_algorithm = &self.object_header.compression_header.algorithm;
		loop {
			if read_bytes == buffer.len() || current_chunk_number > last_chunk_number {
				break;
			}
			let segment = match get_segment_of_chunk_no(current_chunk_number, global_chunkmap) {
				Some(segment_no) => match segments.get_mut(&segment_no) {
					Some(segment) => segment,
					None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
				},
				None => break,
			};
			let enc_information = EncryptionInformation::try_from(&self.object_header).ok();
			//TODO: Check if a bufreader implementation in zffmount is more sufficient by checking this println!.
			//println!("DEBUG: active_filemetadata.position: {}", active_filemetadata.position);
			let chunk_data = get_chunk_data(
				segment, 
				current_chunk_number, 
				&enc_information, 
				compression_algorithm, 
				chunk_size,
				extract_offset_from_preloaded_chunkmap(preloaded_chunkmap, current_chunk_number))?;
			let mut cursor = Cursor::new(&chunk_data[inner_position..]);
			read_bytes += cursor.read(&mut buffer[read_bytes..])?;
			inner_position = 0;
			current_chunk_number += 1;
		}

		active_filemetadata.position += read_bytes as u64;
		Ok(read_bytes)
	}
}

impl Seek for ZffObjectReaderLogical {
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
pub struct ZffObjectReaderVirtual {
	/// Contains the appropriate object header
	object_header: ObjectHeader,
	/// Contains the appropriate object footer of the virtual object
	object_footer: ObjectFooterVirtual,
	/// Cached header of all affected passive objects.
	passive_object_header: BTreeMap<u64, ObjectHeader>,
	/// The virtual object map
	virtual_object_map: BTreeSet<BTreeMap<u64, (u64, u64)>>, 
	/// the internal reader position
	position: u64,
}

impl ZffObjectReaderVirtual {
	/// creates a new [ZffObjectReaderVirtual] with the given metadata.
	pub fn with_data(
		object_header: ObjectHeader,
		object_footer: ObjectFooterVirtual) -> Self {
		Self {
			object_header,
			object_footer,
			passive_object_header: BTreeMap::new(),
			virtual_object_map: BTreeSet::new(), //TODO: Fill this map with the appropriate data :D !!!
			position: 0
		}
	}

	/// checks if the internal map for passive objects is empty. Returns true if, returns false if not.
	pub fn is_passive_object_header_map_empty(&self) -> bool {
		self.passive_object_header.is_empty()
	}

	/// Replaces the internal map of passive objects with the given map.
	pub fn update_passive_object_header_map(&mut self, passive_object_header: BTreeMap<u64, ObjectHeader>) {
		self.passive_object_header = passive_object_header;
	}

	/// Returns a reference of the appropriate [ObjectHeader](crate::header::ObjectHeader).
	pub fn object_header_ref(&self) -> &ObjectHeader {
		&self.object_header
	}

	/// Returns a reference of the appropriate [crate::footer::ObjectFooterVirtual].
	pub fn object_footer_ref(&self) -> &ObjectFooterVirtual {
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

	/// Works like [std::io::Read] for the underlying data, but needs also the segments and the optional preloaded chunkmap.
	pub fn read_with_segments<R: Read + Seek>(
		&mut self, 
		buffer: &mut [u8], 
		segments: &mut HashMap<u64, Segment<R>>,
		preloaded_chunkmap: &PreloadedChunkMap,
		global_chunkmap: &BTreeMap<u64, u64>,
		) -> std::result::Result<usize, std::io::Error> {
		
		let mut read_bytes = 0; // number of bytes which are written to buffer
		
		'outer: loop {
			// find the appropriate mapping information.
			let virtual_mapping_information = match get_vmi_info(
				&self.virtual_object_map, 
				self.position, 
				segments) {
				Ok(mi) => mi,
				Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
			};

			let object_header = get_affected_object_header(&virtual_mapping_information, &self.passive_object_header)?;
			let chunk_size = object_header.chunk_size;
			let mut current_chunk_number = virtual_mapping_information.start_chunk_no;
			let mut inner_position = virtual_mapping_information.chunk_offset as usize; // the inner chunk position
			let mut remaining_offset_length = virtual_mapping_information.length as usize;
			let compression_algorithm = &self.object_header.compression_header.algorithm;

			loop {
				if read_bytes == buffer.len() {
					break 'outer;
				}
				let segment = match get_segment_of_chunk_no(current_chunk_number, global_chunkmap) {
					Some(segment_no) => match segments.get_mut(&segment_no) {
						Some(segment) => segment,
						None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
					},
					None => break,
				};
				let enc_information = EncryptionInformation::try_from(object_header).ok();
				let chunk_data = get_chunk_data(
					segment, 
					current_chunk_number, 
					&enc_information, 
					compression_algorithm, 
					chunk_size,
					extract_offset_from_preloaded_chunkmap(preloaded_chunkmap, current_chunk_number))?;
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

fn get_affected_object_header<'a>(
	virtual_mapping_information: &'a VirtualMappingInformation,
	passive_object_header: &'a BTreeMap<u64, ObjectHeader>) -> std::io::Result<&'a ObjectHeader> {

	let object_number = virtual_mapping_information.object_number;
	let object_header = match passive_object_header.get(&virtual_mapping_information.object_number) {
		Some(header) => header,
		None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, format!("{ERROR_ZFFREADER_MISSING_OBJECT}{object_number}"))),
	};
	Ok(object_header)
}

fn get_vmi_info<R: Read + Seek>(
	vmi_map: &BTreeSet<BTreeMap<u64, (u64, u64)>>, 
	offset: u64,
	segments: &mut HashMap<u64, Segment<R>>) -> Result<VirtualMappingInformation> {
    let (segment_no, offset) = find_vmi_offset(vmi_map, offset).ok_or_else(|| ZffError::new(ZffErrorKind::ValueNotInMap, "VMI not found"))?;
    let segment = match segments.get_mut(&segment_no) {
		Some(segment) => segment,
		None => return Err(ZffError::new(ZffErrorKind::MissingSegment, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
	};
	segment.seek(SeekFrom::Start(offset))?;
	VirtualMappingInformation::decode_directly(segment)
}

impl Seek for ZffObjectReaderVirtual {
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

#[derive(Debug)]
enum PreloadDegree {
	Minimal,
	Recommended,
	All,
}

/// A reader which contains the appropriate metadata of a encrypted object 
/// (e.g. the appropriate [ObjectHeader](crate::header::ObjectHeader) and [ObjectFooter](crate::footer::ObjectFooter)).
#[derive(Debug)]
pub struct ZffObjectReaderEncrypted {
	encrypted_header: EncryptedObjectHeader,
	encrypted_footer: EncryptedObjectFooter,
}

impl ZffObjectReaderEncrypted {
	/// creates a new [ZffObjectReaderEncrypted] with the given metadata.
	pub fn with_data(encrypted_header: EncryptedObjectHeader, encrypted_footer: EncryptedObjectFooter) -> Self {
		Self {
			encrypted_header,
			encrypted_footer,
		}
	}

	/// Tries to decrypt the [ZffObjectReader] with the given parameters.
	pub fn decrypt_with_password<P, R>(&mut self, password: P, segments: &mut HashMap<u64, Segment<R>>
		) -> Result<ZffObjectReader> 
	where
		P: AsRef<[u8]>,
		R: Read + Seek,
	{
		let decrypted_object_header = self.encrypted_header.decrypt_with_password(password)?;

		let enc_info = EncryptionInformation::try_from(&decrypted_object_header)?;

		let decrypted_footer = self.encrypted_footer.decrypt(enc_info.encryption_key, enc_info.algorithm)?;

		let obj_reader = match decrypted_footer {
			ObjectFooter::Physical(physical) => ZffObjectReader::Physical(Box::new(
				ZffObjectReaderPhysical::with_obj_metadata(decrypted_object_header, physical))),
			ObjectFooter::Logical(logical) => ZffObjectReader::Logical(Box::new(
				ZffObjectReaderLogical::with_obj_metadata_recommended(decrypted_object_header, logical, segments)?)),
			ObjectFooter::Virtual(virt) => ZffObjectReader::Virtual(Box::new(
				ZffObjectReaderVirtual::with_data(decrypted_object_header, virt)))
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