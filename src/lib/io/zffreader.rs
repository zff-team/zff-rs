// - STD
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
	header::{HashHeader, EncryptionInformation, SegmentHeader, EncryptedObjectHeader},
	ChunkContent,
};

use crate::{
	ERROR_MISSING_SEGMENT_MAIN_FOOTER,
	ERROR_ZFFREADER_SEGMENT_NOT_FOUND,
	ERROR_MISMATCH_ZFF_VERSION,
	ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION,
	ERROR_MISSING_FILE_NUMBER,
};

use super::*;

// - external
use redb::{Database};

enum PreloadedChunkMap {
	None,
	InMemory(HashMap<u64, u64>), //<Chunknumber, offset>,
	Redb(Database),
}

pub struct ZffReader<R: Read + Seek> {
	segments: HashMap<u64, Segment<R>>, //<segment number, Segment>
	object_reader: HashMap<u64, ZffObjectReader>, //<object_number, ZffObjectReader>,
	main_footer: MainFooter,
	chunk_map: PreloadedChunkMap,
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
		})
	}

	//TODO: fn list_objects() -> BTreeMap<u64, ObjectInfo>
	//			-> ObjectInfo -> Number, Type: [Physical, Logical, Encrypted], Option<(first, last)> chunknumber, Option<Number of files>
	pub fn list_objects(&self) -> BTreeMap<u64, u64> {
		self.main_footer.object_footer().clone()
	}

	pub fn number_of_chunks(&self) -> u64 {
		let (chunk_number, _) = self.main_footer.chunk_maps().last_key_value().unwrap_or((&0, &0));
		*chunk_number
	}

	//TODO: set_preload_chunkmap_in_memory() //and convert from Redb, if exists
	pub fn set_preload_chunkmap_mode_in_memory(&mut self) {
		match &self.chunk_map {
			PreloadedChunkMap::None => self.chunk_map = PreloadedChunkMap::InMemory(HashMap::new()),
			PreloadedChunkMap::InMemory(_) => (),
			PreloadedChunkMap::Redb(_db) => todo!(),
		}
	}
	//TODO: set_preload_chunkmap_redb(Redb connection) // and convert from in-memory, if exists
	//TODO: preload_chunkmap(first: u64, last: u64), //if PreloadChunkMap::None is set, InMemory will be used automatically.
	//TODO: preload_chunkmap_full() //if PreloadChunkMap::None is set, InMemory will be used automatically.
}

pub(crate) enum ZffObjectReader {
	Physical(Box<ZffObjectReaderPhysical>),
	Logical(Box<ZffObjectReaderLogical>),
	Encrypted(Box<ZffObjectReaderEncrypted>),
}

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
			let fileheader = match segments.get_mut(&header_segment_number) {
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
			let filefooter = match segments.get_mut(&footer_segment_number) {
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
	pub fn set_active_file(&self, filenumber: u64) -> Result<()> {
		match self.files.get(&filenumber) {
			Some(_) => Ok(()),
			None => Err(ZffError::new(ZffErrorKind::MissingFileNumber, filenumber.to_string()))
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

enum PreloadDegree {
	Minimal,
	Recommended,
	All,
}

/// to convert into an unencrypted Object...?
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
}

struct FileMetadata {
	parent_file_number: u64,
	length_of_data: u64,
	first_chunk_number: u64,
	number_of_chunks: u64,
	position: u64,
	file_type: Option<FileType>,
	filename: Option<String>,
	metadata_ext: HashMap<String, String>,
	acquisition_start: Option<u64>,
	acquisition_end: Option<u64>,
	hash_header: Option<HashHeader>,
}

impl FileMetadata {
	pub fn with_header_minimal(fileheader: &FileHeader, filefooter: &FileFooter) -> Self {
		Self {
			parent_file_number: fileheader.parent_file_number,
			length_of_data: filefooter.length_of_data(),
			first_chunk_number: filefooter.first_chunk_number(),
			number_of_chunks: filefooter.number_of_chunks(),
			position: 0,
			file_type: None,
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
			file_type: Some(fileheader.file_type.clone()),
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
			file_type: Some(fileheader.file_type.clone()),
			filename: Some(fileheader.filename.clone()),
			metadata_ext: extract_recommended_metadata(fileheader),
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
								segments,
								main_footer)
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
	main_footer: &MainFooter,
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