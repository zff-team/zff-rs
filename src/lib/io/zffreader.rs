// - STD
use std::fmt;
use std::borrow::Borrow;
use std::io::{Read, Seek, SeekFrom, Cursor};
use std::collections::{HashMap, BTreeMap};

// - internal
use crate::{
	Result,
	Segment,
	HeaderCoding,
	ValueDecoder,
	ZffError,
	ZffErrorKind,
	footer::{
		MainFooter, 
		ObjectFooterPhysical,
		ObjectFooterLogical,
		FileFooter,
		SegmentFooter,
		EncryptedObjectFooter,
		ObjectFooter,
	},
	header::{HashHeader, EncryptionInformation, SegmentHeader, EncryptedObjectHeader, ObjectType as HeaderObjectType},
	ChunkContent,
};

use crate::{
	PRELOADED_CHUNK_MAP_TABLE,
	ERROR_MISSING_SEGMENT_MAIN_FOOTER,
	ERROR_ZFFREADER_SEGMENT_NOT_FOUND,
	ERROR_LAST_GREATER_FIRST,
	ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION,
	ERROR_MISSING_FILE_NUMBER,
	ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT,
	ERROR_ZFFREADER_MISSING_OBJECT,
	ERROR_ZFFREADER_OPERATION_PHYSICAL_OBJECT,
};

use super::*;

// - external
use redb::{Database, ReadableTable};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ObjectType {
	Physical,
	Logical,
	Encrypted,
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    	let value = match self {
    		ObjectType::Physical => "physical",
    		ObjectType::Logical => "logical",
    		ObjectType::Encrypted => "encrypted",
    	};
        write!(f, "{value}")
    }
}

#[derive(Debug)]
enum PreloadedChunkMap {
	None,
	InMemory(HashMap<u64, u64>), //<Chunknumber, offset>,
	Redb(Database),
}

#[derive(Debug)]
pub struct ZffReader<R: Read + Seek> {
	segments: HashMap<u64, Segment<R>>, //<segment number, Segment>
	object_reader: HashMap<u64, ZffObjectReader>, //<object_number, ZffObjectReader>,
	main_footer: MainFooter,
	chunk_map: PreloadedChunkMap,
	active_object: u64, //the number of the active object.
}

impl<R: Read + Seek> ZffReader<R> {
	pub fn with_reader(reader_vec: Vec<R>) -> Result<Self> {
		let mut segments = HashMap::new();
		let mut main_footer = None;

		for mut reader in reader_vec {
			let segment_header = SegmentHeader::decode_directly(&mut reader)?;
			let segment_footer = match try_find_footer(&mut reader)? {
				Footer::MainAndSegment((main, segment)) => {
					main_footer = Some(main);
					segment
				},
				Footer::Segment(segment_footer) => segment_footer,
			};

			let segment_number = segment_header.segment_number;

			let segment = Segment::with_header_and_data(segment_header, reader, segment_footer);
			segments.insert(segment_number, segment);
		}

		let main_footer = match main_footer {
			Some(footer) => footer,
			None => return Err(ZffError::new(ZffErrorKind::MissingSegment, ERROR_MISSING_SEGMENT_MAIN_FOOTER)),
		};
		
		Ok(Self {
			segments,
			object_reader: HashMap::new(),
			main_footer,
			chunk_map: PreloadedChunkMap::None,
			active_object: 0,
		})
	}

	pub fn list_objects(&mut self) -> Result<BTreeMap<u64, ObjectType>> {
		let mut map = BTreeMap::new();
		for (object_number, segment_number) in self.main_footer.object_header() {
			let segment = match self.segments.get_mut(segment_number) {
				Some(segment) => segment,
				None => return Err(ZffError::new(ZffErrorKind::MissingSegment, segment_number.to_string())),
			};
			if let Ok(obj_header) = segment.read_object_header(*object_number) {
				let obj_type = match obj_header.object_type {
					HeaderObjectType::Physical => ObjectType::Physical,
					HeaderObjectType::Logical => ObjectType::Logical,
				};
				map.insert(*object_number, obj_type);
			} else {
				match segment.read_encrypted_object_header(*object_number) {
					Ok(_) => map.insert(*object_number, ObjectType::Encrypted),
					Err(e) => return Err(e),
				};
			}
		}
		Ok(map)
	}

	pub fn set_active_object(&mut self, object_number: u64) -> Result<()> {
		if self.object_reader.get(&object_number).is_some() {
			self.active_object = object_number;
			Ok(())
		} else {
			Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string()))
		}
	}

	pub fn set_active_file(&mut self, filenumber: u64) -> Result<()> {
		if let Some(object_reader) = self.object_reader.get_mut(&self.active_object) {
			match object_reader {
				ZffObjectReader::Logical(reader) => reader.set_active_file(filenumber),
				_ => Err(ZffError::new(ZffErrorKind::MismatchObjectType, self.active_object.to_string())) //TODO: return object type instead of object_number,
			}
		} else {
			Err(ZffError::new(ZffErrorKind::MissingObjectNumber, self.active_object.to_string()))
		}
	}

	pub fn initialize_object(&mut self, object_number: u64) -> Result<()> {
		let object_reader = initialize_object_reader(object_number, &mut self.segments, &self.main_footer)?;
		self.object_reader.insert(object_number, object_reader);
		Ok(())
	}

	pub fn initialize_objects_all(&mut self) -> Result<()> {
		let object_reader_map = initialize_object_reader_all(&mut self.segments, &self.main_footer)?;
		self.object_reader = object_reader_map;
		Ok(())
	}

	pub fn number_of_chunks(&self) -> u64 {
		let (chunk_number, _) = self.main_footer.chunk_maps().last_key_value().unwrap_or((&0, &0));
		*chunk_number
	}

	pub fn decrypt_object<P: AsRef<[u8]>>(&mut self, object_number: u64, decryption_password: P) -> Result<ObjectType> {
		let object_reader = match self.object_reader.get_mut(&object_number) {
			Some(reader) => reader,
			None => return Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string())),
		};
		let decrypted_reader = match object_reader {
			ZffObjectReader::Encrypted(reader) => reader.decrypt_with_password(decryption_password, self.main_footer.chunk_maps(), &mut self.segments)?,
			_ => return Err(ZffError::new(ZffErrorKind::NoEncryptionDetected, object_number.to_string()))
		};
		let o_type = match decrypted_reader {
			ZffObjectReader::Physical(_) => ObjectType::Physical,
			ZffObjectReader::Logical(_) => ObjectType::Logical,
			ZffObjectReader::Encrypted(_) => ObjectType::Encrypted,
		};
		self.object_reader.insert(object_number, decrypted_reader);
		Ok(o_type)
	}


	pub fn set_preload_chunkmap_mode_in_memory(&mut self) -> Result<()> {
		match &mut self.chunk_map {
			PreloadedChunkMap::None => self.chunk_map = PreloadedChunkMap::InMemory(HashMap::new()),
			PreloadedChunkMap::InMemory(_) => (),
			PreloadedChunkMap::Redb(ref mut db) => self.chunk_map = PreloadedChunkMap::InMemory(extract_redb_map(db)?),
		}
		Ok(())
	}

	pub fn set_preload_chunkmap_mode_redb(&mut self, mut db: Database) -> Result<()> {
		match &self.chunk_map {
			PreloadedChunkMap::Redb(_) => return Ok(()),
			PreloadedChunkMap::None => initialize_redb_chunkmap(&mut db, &HashMap::new())?,
			PreloadedChunkMap::InMemory(map) => initialize_redb_chunkmap(&mut db, map)?,
		}
		self.chunk_map = PreloadedChunkMap::Redb(db);
		Ok(())
	}
	
	pub fn preload_chunkmap(&mut self, first: u64, last: u64) -> Result<()> {
		// check if chunk numbers are valid.
		if first == 0 {
			return Err(ZffError::new(ZffErrorKind::InvalidChunkNumber, first.to_string()));
		} else if first > last {
			return Err(ZffError::new(ZffErrorKind::InvalidChunkNumber, ERROR_LAST_GREATER_FIRST));
		} else if last > self.number_of_chunks() {
			return Err(ZffError::new(ZffErrorKind::InvalidChunkNumber, last.to_string()));	
		}

		//try to reserve the additional size, if PreloadedChunkMap::InMemory is used.
		let mut size = last - first;
		match &mut self.chunk_map {
			PreloadedChunkMap::None => {
				let mut map = HashMap::new();
				map.try_reserve(size as usize)?;
				self.chunk_map = PreloadedChunkMap::InMemory(map)
			},
			PreloadedChunkMap::Redb(_) => (),
			PreloadedChunkMap::InMemory(map) => {
				for chunk_no in first..=last {
					if map.contains_key(&chunk_no) {
						size -= 1;
					}
				}
				map.try_reserve(size as usize)?;
			}
		}

		for chunk_no in first..=last {
			let segment = match get_segment_of_chunk_no(chunk_no, self.main_footer.chunk_maps()) {
				Some(segment_no) => match self.segments.get_mut(&segment_no) {
					Some(segment) => segment,
					None => return Err(ZffError::new(ZffErrorKind::MissingSegment, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
				},
				None => return Err(ZffError::new(ZffErrorKind::InvalidChunkNumber, chunk_no.to_string())),
			};
			let offset = segment.get_chunk_offset(&chunk_no)?;
			match &mut self.chunk_map {
				PreloadedChunkMap::None => unreachable!(),
				PreloadedChunkMap::InMemory(map) => { map.insert(chunk_no, offset); },
				PreloadedChunkMap::Redb(db) => preloaded_redb_chunkmap_add_entry(db, chunk_no, offset)?,
			};
		}

		if let PreloadedChunkMap::InMemory(map) = &mut self.chunk_map { map.shrink_to_fit() }
		Ok(())
	}

	pub fn preload_chunkmap_full(&mut self) -> Result<()> {
		let first = 1;
		let last = self.number_of_chunks();
		self.preload_chunkmap(first, last)
	}

	pub fn current_filemetadata(&self) -> Result<&FileMetadata> {
		match self.object_reader.get(&self.active_object) {
			Some(ZffObjectReader::Logical(reader)) => {
				Ok(reader.filemetadata()?)
			},
			Some(ZffObjectReader::Physical(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_PHYSICAL_OBJECT)),
			Some(ZffObjectReader::Encrypted(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
			None => Err(ZffError::new(ZffErrorKind::MissingObjectNumber, self.active_object.to_string())),
		}
	}

	pub fn current_fileheader(&mut self) -> Result<FileHeader> {
		match self.object_reader.get(&self.active_object) {
			Some(ZffObjectReader::Logical(reader)) => {
				reader.current_fileheader(&mut self.segments)
			},
			Some(ZffObjectReader::Physical(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_PHYSICAL_OBJECT)),
			Some(ZffObjectReader::Encrypted(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
			None => Err(ZffError::new(ZffErrorKind::MissingObjectNumber, self.active_object.to_string())),
		}
	}

	pub fn current_filefooter(&mut self) -> Result<FileFooter> {
		match self.object_reader.get(&self.active_object) {
			Some(ZffObjectReader::Logical(reader)) => {
				reader.current_filefooter(&mut self.segments)
			},
			Some(ZffObjectReader::Physical(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_PHYSICAL_OBJECT)),
			Some(ZffObjectReader::Encrypted(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
			None => Err(ZffError::new(ZffErrorKind::MissingObjectNumber, self.active_object.to_string())),
		}
	}

	pub fn active_object_header_ref(&self) -> Result<&ObjectHeader> {
		match self.get_active_reader()? {
			ZffObjectReader::Physical(reader) => Ok(reader.object_header_ref()),
			ZffObjectReader::Logical(reader) => Ok(reader.object_header_ref()),
			ZffObjectReader::Encrypted(_) => Err(ZffError::new(ZffErrorKind::InvalidOption, "")) //TODO: Error msg
		}
	}

	pub fn active_object_footer(&self) -> Result<ObjectFooter> {
		match self.get_active_reader()? {
			ZffObjectReader::Physical(reader) => Ok(reader.object_footer()),
			ZffObjectReader::Logical(reader) => Ok(reader.object_footer()),
			ZffObjectReader::Encrypted(_) => Err(ZffError::new(ZffErrorKind::InvalidOption, "")) //TODO: Error msg
		}
	}

	fn get_active_reader(&self) -> Result<&ZffObjectReader> {
		match self.object_reader.get(&self.active_object) {
			Some(reader) => Ok(reader),
			None => Err(ZffError::new(ZffErrorKind::MissingObjectNumber, self.active_object.to_string())),
		}
	}

	pub fn segment_mut_ref(&mut self, segment_number: u64) -> Result<&mut Segment<R>> {
		match self.segments.get_mut(&segment_number) {
			Some(segment) => Ok(segment),
			None => Err(ZffError::new(ZffErrorKind::MissingSegment, segment_number.to_string()))
		}
	}
}

impl<R: Read + Seek> Read for ZffReader<R> {
	fn read(&mut self, buffer: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
		let object_reader = match self.object_reader.get_mut(&self.active_object) {
			Some(object_reader) => object_reader,
			None => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{ERROR_ZFFREADER_MISSING_OBJECT}{}", self.active_object)))
		};
		match object_reader {
			ZffObjectReader::Physical(reader) => reader.read_with_segments(buffer, &mut self.segments),
			ZffObjectReader::Logical(reader) => reader.read_with_segments(buffer, &mut self.segments),
			ZffObjectReader::Encrypted(_) => Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
		}
	}
}


impl<R: Read + Seek> Seek for ZffReader<R> {
	fn seek(&mut self, seek_from: SeekFrom) -> std::result::Result<u64, std::io::Error> {
		let object_reader = match self.object_reader.get_mut(&self.active_object) {
			Some(object_reader) => object_reader,
			None => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{ERROR_ZFFREADER_MISSING_OBJECT}{}", self.active_object)))
		};
		object_reader.seek(seek_from)
	}
}

#[derive(Debug)]
pub(crate) enum ZffObjectReader {
	Physical(Box<ZffObjectReaderPhysical>),
	Logical(Box<ZffObjectReaderLogical>),
	Encrypted(Box<ZffObjectReaderEncrypted>),
}

impl Seek for ZffObjectReader {
	fn seek(&mut self, seek_from: std::io::SeekFrom) -> std::result::Result<u64, std::io::Error> {
		match self {
			ZffObjectReader::Physical(reader) => reader.seek(seek_from),
			ZffObjectReader::Logical(reader) => reader.seek(seek_from),
			ZffObjectReader::Encrypted(_) => Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
		}
	}
}

#[derive(Debug)]
pub(crate) struct ZffObjectReaderPhysical {
	object_header: ObjectHeader,
	object_footer: ObjectFooterPhysical,
	global_chunkmap: BTreeMap<u64, u64>,
	position: u64
}

impl ZffObjectReaderPhysical {
	pub(crate) fn with_obj_metadata(
		object_header: ObjectHeader, 
		object_footer: ObjectFooterPhysical,
		global_chunkmap: BTreeMap<u64, u64>, //TODO: only used in read_with_segments. Could also be a &-paramter for the specific method?
		) -> Self {
		Self {
			object_header,
			object_footer,
			global_chunkmap,
			position: 0
		}
	}

	pub(crate) fn object_header_ref(&self) -> &ObjectHeader {
		&self.object_header
	}

	pub(crate) fn object_footer(&self) -> ObjectFooter {
		ObjectFooter::Physical(self.object_footer.clone())
	}

	fn read_with_segments<R: Read + Seek>(
		&mut self, 
		buffer: &mut [u8], 
		segments: &mut HashMap<u64, Segment<R>>
		) -> std::result::Result<usize, std::io::Error> {
		let chunk_size = self.object_header.chunk_size;
		let first_chunk_number = self.object_footer.first_chunk_number;
		let last_chunk_number = first_chunk_number + self.object_footer.number_of_chunks - 1;
		let mut current_chunk_number = (first_chunk_number * chunk_size + self.position) / chunk_size;
		let mut inner_position = (self.position % chunk_size) as usize; // the inner chunk position
		let mut read_bytes = 0; // number of bytes which are written to buffer
		let compression_algorithm = self.object_header.compression_header.algorithm();

		loop {
			if read_bytes == buffer.len() || current_chunk_number > last_chunk_number {
				break;
			}
			let segment = match get_segment_of_chunk_no(current_chunk_number, &self.global_chunkmap) {
				Some(segment_no) => match segments.get_mut(&segment_no) {
					Some(segment) => segment,
					None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
				},
				None => break,
			};
			let enc_information = EncryptionInformation::try_from(&self.object_header).ok();
			let chunk_data = get_chunk_data(segment, current_chunk_number, &enc_information, compression_algorithm, chunk_size)?;
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

#[derive(Debug)]
pub struct ZffObjectReaderLogical {
	object_header: ObjectHeader,
	object_footer: ObjectFooterLogical,
	global_chunkmap: BTreeMap<u64, u64>, //TODO: only used in read_with_segments. Could also be a &-paramter for the specific method?
	active_file: u64, // filenumber of active file
	files: HashMap<u64, FileMetadata>//<filenumber, metadata>
}

impl ZffObjectReaderLogical {
	pub fn with_obj_metadata_minimal<R: Read + Seek>(
		object_header: ObjectHeader, 
		object_footer: ObjectFooterLogical,
		segments: &mut HashMap<u64, Segment<R>>, //<segment number, Segment-object>
		global_chunkmap: BTreeMap<u64, u64>,
		) -> Result<Self> {
		Self::with_obj_metadata(object_header, object_footer, segments, global_chunkmap, PreloadDegree::Minimal)
	}

	pub fn with_obj_metadata_recommended<R: Read + Seek>(
		object_header: ObjectHeader, 
		object_footer: ObjectFooterLogical,
		segments: &mut HashMap<u64, Segment<R>>, //<segment number, Segment-object>
		global_chunkmap: BTreeMap<u64, u64>,
		) -> Result<Self> {
		Self::with_obj_metadata(object_header, object_footer, segments, global_chunkmap, PreloadDegree::Recommended)
	}

	pub fn with_obj_metadata_all<R: Read + Seek>(
		object_header: ObjectHeader, 
		object_footer: ObjectFooterLogical,
		segments: &mut HashMap<u64, Segment<R>>, //<segment number, Segment-object>
		global_chunkmap: BTreeMap<u64, u64>,
		) -> Result<Self> {
		Self::with_obj_metadata(object_header, object_footer, segments, global_chunkmap, PreloadDegree::All)
	}

	pub(crate) fn object_header_ref(&self) -> &ObjectHeader {
		&self.object_header
	}

	pub(crate) fn object_footer(&self) -> ObjectFooter {
		ObjectFooter::Logical(self.object_footer.clone())
	}

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
			Some(EncryptionInformation::new(key, encryption_header.algorithm().clone()))
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
			Some(EncryptionInformation::new(key, encryption_header.algorithm().clone()))
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
		global_chunkmap: BTreeMap<u64, u64>,
		degree_value: PreloadDegree,
		) -> Result<Self> {

		let enc_info = if let Some(encryption_header) = &object_header.encryption_header {
			let key = match encryption_header.get_encryption_key() {
				Some(key) => key,
				None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, "")),
			};
			Some(EncryptionInformation::new(key, encryption_header.algorithm().clone()))
		} else {
			None
		};

		// reads all file header and appropriate footer and fill the files-map. Sets the File number 1 active.
		let mut files = HashMap::new();
		for (filenumber, header_segment_number) in object_footer.file_header_segment_numbers() {
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

		Ok(Self {
			object_header,
			object_footer,
			active_file: 1,
			files,
			global_chunkmap,
		})
	}

	/// # Error
	/// fails if no appropriate file for the given filenumber exists.
	pub fn set_active_file(&mut self, filenumber: u64) -> Result<()> {
		match self.files.get(&filenumber) {
			Some(_) => self.active_file = filenumber,
			None => return Err(ZffError::new(ZffErrorKind::MissingFileNumber, filenumber.to_string()))
		}
		Ok(())
	}

	fn filemetadata(&self) -> Result<&FileMetadata> {
		match self.files.get(&self.active_file) {
			Some(metadata) => Ok(metadata),
			None => Err(ZffError::new(ZffErrorKind::MissingFileNumber, self.active_file.to_string()))
		}
	}

	fn read_with_segments<R: Read + Seek>(
		&mut self, 
		buffer: &mut [u8], 
		segments: &mut HashMap<u64, Segment<R>>
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
		let compression_algorithm = self.object_header.compression_header.algorithm();
		loop {
			if read_bytes == buffer.len() || current_chunk_number > last_chunk_number {
				break;
			}
			let segment = match get_segment_of_chunk_no(current_chunk_number, &self.global_chunkmap) {
				Some(segment_no) => match segments.get_mut(&segment_no) {
					Some(segment) => segment,
					None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
				},
				None => break,
			};
			let enc_information = EncryptionInformation::try_from(&self.object_header).ok();
			//TODO: Check if a bufreader implementation in zffmount is more sufficient by checking this println!.
			//println!("DEBUG: active_filemetadata.position: {}", active_filemetadata.position);
			let chunk_data = get_chunk_data(segment, current_chunk_number, &enc_information, compression_algorithm, chunk_size)?;
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

#[derive(Debug)]
enum PreloadDegree {
	Minimal,
	Recommended,
	All,
}

#[derive(Debug)]
pub(crate) struct ZffObjectReaderEncrypted {
	encrypted_header: EncryptedObjectHeader,
	encrypted_footer: EncryptedObjectFooter,
}

impl ZffObjectReaderEncrypted {
	fn with_data(encrypted_header: EncryptedObjectHeader, encrypted_footer: EncryptedObjectFooter) -> Self {
		Self {
			encrypted_header,
			encrypted_footer,
		}
	}

	fn decrypt_with_password<P, R>(&mut self, password: P, global_chunkmap: &BTreeMap<u64, u64>, segments: &mut HashMap<u64, Segment<R>>
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
				ZffObjectReaderPhysical::with_obj_metadata(decrypted_object_header, physical, global_chunkmap.clone()))),
			ObjectFooter::Logical(logical) => ZffObjectReader::Logical(Box::new(
			ZffObjectReaderLogical::with_obj_metadata_recommended(decrypted_object_header, logical, segments, global_chunkmap.clone())?)), //TODO: use enum to provide also minimal and full.
		};

		Ok(obj_reader)

	}
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FileMetadata {
	pub parent_file_number: u64,
	pub length_of_data: u64,
	pub first_chunk_number: u64,
	pub number_of_chunks: u64,
	pub position: u64,
	pub file_type: FileType,
	pub filename: Option<String>,
	pub metadata_ext: HashMap<String, String>,
	pub acquisition_start: Option<u64>,
	pub acquisition_end: Option<u64>,
	pub hash_header: Option<HashHeader>,
}

impl FileMetadata {
	pub fn with_header_minimal(fileheader: &FileHeader, filefooter: &FileFooter) -> Self {
		Self {
			parent_file_number: fileheader.parent_file_number,
			length_of_data: filefooter.length_of_data(),
			first_chunk_number: filefooter.first_chunk_number(),
			number_of_chunks: filefooter.number_of_chunks(),
			position: 0,
			file_type: fileheader.file_type.clone(),
			filename: None,
			metadata_ext: HashMap::new(),
			acquisition_start: None,
			acquisition_end: None,
			hash_header: None,
		}
	}

	pub fn with_header_recommended(fileheader: &FileHeader, filefooter: &FileFooter) -> Self {
		Self {
			parent_file_number: fileheader.parent_file_number,
			length_of_data: filefooter.length_of_data(),
			first_chunk_number: filefooter.first_chunk_number(),
			number_of_chunks: filefooter.number_of_chunks(),
			position: 0,
			file_type: fileheader.file_type.clone(),
			filename: Some(fileheader.filename.clone()),
			metadata_ext: extract_recommended_metadata(fileheader),
			acquisition_start: None,
			acquisition_end: None,
			hash_header: None,
		}
	}

	pub fn with_header_all(fileheader: &FileHeader, filefooter: &FileFooter) -> Self {
		Self {
			parent_file_number: fileheader.parent_file_number,
			length_of_data: filefooter.length_of_data(),
			first_chunk_number: filefooter.first_chunk_number(),
			number_of_chunks: filefooter.number_of_chunks(),
			position: 0,
			file_type: fileheader.file_type.clone(),
			filename: Some(fileheader.filename.clone()),
			metadata_ext: extract_all_metadata(fileheader),
			acquisition_start: Some(filefooter.acquisition_start()),
			acquisition_end: Some(filefooter.acquisition_end()),
			hash_header: Some(filefooter.hash_header().clone()),
		}
	}
}

fn extract_recommended_metadata(fileheader: &FileHeader) -> HashMap<String, String> {
	let mut metadata = HashMap::new();
	if let Some(value) = fileheader.metadata_ext.get(METADATA_ATIME) {
		metadata.insert(METADATA_ATIME.to_string(), value.to_string());
	}
	if let Some(value) = fileheader.metadata_ext.get(METADATA_MTIME) {
		metadata.insert(METADATA_MTIME.to_string(), value.to_string());
	}
	if let Some(value) = fileheader.metadata_ext.get(METADATA_CTIME) {
		metadata.insert(METADATA_CTIME.to_string(), value.to_string());
	}
	if let Some(value) = fileheader.metadata_ext.get(METADATA_BTIME) {
		metadata.insert(METADATA_BTIME.to_string(), value.to_string());
	}

	#[cfg(target_os = "linux")]
	if let Some(value) = fileheader.metadata_ext.get(METADATA_EXT_KEY_UID) {
		metadata.insert(METADATA_EXT_KEY_UID.to_string(), value.to_string());
	}
	#[cfg(target_os = "linux")]
	if let Some(value) = fileheader.metadata_ext.get(METADATA_EXT_KEY_GID) {
		metadata.insert(METADATA_EXT_KEY_GID.to_string(), value.to_string());
	}
	#[cfg(target_os = "linux")]
	if let Some(value) = fileheader.metadata_ext.get(METADATA_EXT_KEY_MODE) {
		metadata.insert(METADATA_EXT_KEY_MODE.to_string(), value.to_string());
	}

	metadata
}

fn extract_all_metadata(fileheader: &FileHeader) -> HashMap<String, String> {
	fileheader.metadata_ext.clone()
}

fn get_segment_of_chunk_no(chunk_no: u64, global_chunkmap: &BTreeMap<u64, u64>) -> Option<u64> {
    // If the chunk_no is exactly matched, return the corresponding value.
    if let Some(&value) = global_chunkmap.get(&chunk_no) {
        return Some(value);
    }

    // If the chunk_no is higher than the highest key, return None.
    if let Some((&highest_chunk_no, _)) = global_chunkmap.iter().next_back() {
        if chunk_no > highest_chunk_no {
            return None;
        }
    }

    // Find the next higher key and return its value.
    if let Some((_, &segment_no)) = global_chunkmap.iter().find(|(&key, _)| key > chunk_no) {
        return Some(segment_no);
    }

    // If no next higher key is found, it means the chunk_no is higher than all keys,
    // so we should return None.
    None
}

enum Footer {
	Segment(SegmentFooter),
	MainAndSegment((MainFooter, SegmentFooter))
}

fn try_find_footer<R: Read + Seek>(reader: &mut R) -> Result<Footer> {
	let position = reader.stream_position()?;
	reader.seek(SeekFrom::End(-8))?; //seeks to the end to reads the last 8 bytes (footer offset)
	let mut footer_offset = u64::decode_directly(reader)?;
	reader.seek(SeekFrom::Start(footer_offset))?;
	if let Ok(segment_footer) = SegmentFooter::decode_directly(reader) {
		reader.seek(SeekFrom::Start(position))?;
		return Ok(Footer::Segment(segment_footer));
	}
	reader.seek(SeekFrom::Start(footer_offset))?;
	if let Ok(main_footer) = MainFooter::decode_directly(reader) {
		reader.seek(SeekFrom::Start(footer_offset))?;
		reader.seek(SeekFrom::Current(-8))?; //seeks to the footer offset of the segment footer
		footer_offset = u64::decode_directly(reader)?;
		reader.seek(SeekFrom::Start(footer_offset))?;
		if let Ok(segment_footer) = SegmentFooter::decode_directly(reader) {
			reader.seek(SeekFrom::Start(position))?;
			Ok(Footer::MainAndSegment((main_footer, segment_footer)))
		} else {
			reader.seek(SeekFrom::Start(position))?;
			Err(ZffError::new(ZffErrorKind::MalformedSegment, ""))
		}
	} else {
		reader.seek(SeekFrom::Start(position))?;
		Err(ZffError::new(ZffErrorKind::MalformedSegment, ""))
	}
}

fn get_chunk_data<C, R>(
	segment: &mut Segment<R>, 
	current_chunk_number: u64, 
	enc_information: &Option<EncryptionInformation>,
	compression_algorithm: C,
	chunk_size: u64,
	) -> std::result::Result<Vec<u8>, std::io::Error>
where
	C: Borrow<CompressionAlgorithm> + std::marker::Copy,
	R: Read + Seek
{
	let chunk_content = match segment.chunk_data(current_chunk_number, enc_information, compression_algorithm) {
		Ok(data) => data,
		Err(e) => match e.unwrap_kind() {
			ZffErrorKind::IoError(io_error) => return Err(io_error),
			error => return Err(std::io::Error::new(std::io::ErrorKind::Other, error.to_string())) 
		},
	};
	match chunk_content {
		ChunkContent::Raw(data) => Ok(data),
		ChunkContent::SameBytes(single_byte) => Ok(vec![single_byte; chunk_size as usize]),
		ChunkContent::Duplicate(dup_chunk_no) => {
			get_chunk_data(segment, dup_chunk_no, enc_information, compression_algorithm, chunk_size)
		}
	}
}


fn initialize_object_reader_all<R: Read + Seek>(
	segments: &mut HashMap<u64, Segment<R>>, 
	main_footer: &MainFooter
	) -> Result<HashMap<u64, ZffObjectReader>> {

	let mut obj_reader_map = HashMap::new();
	for obj_no in main_footer.object_footer().keys() {
		let obj_reader = initialize_object_reader(*obj_no, segments, main_footer)?;
		obj_reader_map.insert(*obj_no, obj_reader);
	}
	Ok(obj_reader_map)
}

fn initialize_object_reader<R: Read + Seek>(
	object_number: u64,
	segments: &mut HashMap<u64, Segment<R>>,
	main_footer: &MainFooter,
	) -> Result<ZffObjectReader> {
	let segment_no_footer = match main_footer.object_footer().get(&object_number) {
		None => return Err(ZffError::new(ZffErrorKind::MalformedSegment, "")),
		Some(segment_no) => segment_no
	};
	let segment_no_header = match main_footer.object_header().get(&object_number) {
		None => return Err(ZffError::new(ZffErrorKind::MalformedSegment, "")),
		Some(segment_no) => segment_no
	};

	match segments.get_mut(segment_no_header) {
		None => Err(ZffError::new(ZffErrorKind::MissingSegment, segment_no_header.to_string())),
		Some(segment) => if segment.read_object_header(object_number).is_ok() {
							initialize_unencrypted_object_reader(
								object_number,
								*segment_no_header,
								*segment_no_footer,
								segments,
								main_footer)
						} else {
							initialize_encrypted_object_reader(
								object_number,
								*segment_no_header,
								*segment_no_footer,
								segments)
						},
	}
}

fn initialize_unencrypted_object_reader<R: Read + Seek>(
	obj_number: u64,
	header_segment_no: u64,
	footer_segment_no: u64,
	segments: &mut HashMap<u64, Segment<R>>,
	main_footer: &MainFooter,
	) -> Result<ZffObjectReader> {



	let header = match segments.get_mut(&header_segment_no) {
		None => return Err(ZffError::new(ZffErrorKind::MissingSegment, header_segment_no.to_string())),
		Some(segment) => segment.read_object_header(obj_number)?,
	};

	let footer = match segments.get_mut(&footer_segment_no) {
		None => return Err(ZffError::new(ZffErrorKind::MissingSegment, header_segment_no.to_string())),
		Some(segment) => segment.read_object_footer(obj_number)?,
	};

	let obj_reader = match footer {
		ObjectFooter::Physical(physical) => ZffObjectReader::Physical(Box::new(ZffObjectReaderPhysical::with_obj_metadata(header, physical, main_footer.chunk_maps().clone()))),
		ObjectFooter::Logical(logical) => ZffObjectReader::Logical(Box::new(ZffObjectReaderLogical::with_obj_metadata_recommended(header, logical, segments, main_footer.chunk_maps().clone())?)), //TODO: use enum to provide also minimal and full.
	};
	Ok(obj_reader)
}

fn initialize_encrypted_object_reader<R: Read + Seek>(
	obj_number: u64,
	header_segment_no: u64,
	footer_segment_no: u64,
	segments: &mut HashMap<u64, Segment<R>>,
	) -> Result<ZffObjectReader> {



	let header = match segments.get_mut(&header_segment_no) {
		None => return Err(ZffError::new(ZffErrorKind::MissingSegment, header_segment_no.to_string())),
		Some(segment) => segment.read_encrypted_object_header(obj_number)?,
	};

	let footer = match segments.get_mut(&footer_segment_no) {
		None => return Err(ZffError::new(ZffErrorKind::MissingSegment, header_segment_no.to_string())),
		Some(segment) => segment.read_encrypted_object_footer(obj_number)?,
	};

	let obj_reader = ZffObjectReader::Encrypted(Box::new(ZffObjectReaderEncrypted::with_data(header, footer)));
	Ok(obj_reader)
}

fn extract_redb_map(db: &mut Database) -> Result<HashMap<u64, u64>> {
	 let mut new_map = HashMap::new();
	 let read_txn = db.begin_read()?;
	 let table = read_txn.open_table(PRELOADED_CHUNK_MAP_TABLE)?;
	 let mut table_iterator = table.iter()?;
	 while let Some(data) = table_iterator.next_back() {
	 	let (key, value) = data?;
	 	new_map.insert(key.value(), value.value());
	 }
	 Ok(new_map)
}

fn initialize_redb_chunkmap(db: &mut Database, map: &HashMap<u64, u64>) -> Result<()> {
	let write_txn = db.begin_write()?;
	{
		let mut table = write_txn.open_table(PRELOADED_CHUNK_MAP_TABLE)?;
		for (key, value) in map {
			table.insert(key, value)?;
		}
	}
	write_txn.commit()?;
	Ok(())
}

fn preloaded_redb_chunkmap_add_entry(db: &mut Database, chunk_no: u64, offset: u64) -> Result<()> {
	let write_txn = db.begin_write()?;
	{
		let mut table = write_txn.open_table(PRELOADED_CHUNK_MAP_TABLE)?;
		table.insert(chunk_no, offset)?;
	}
	write_txn.commit()?;
	Ok(())
}