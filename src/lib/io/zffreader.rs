// - STD
use std::fmt;
use std::borrow::Borrow;
use std::io::{Read, Seek, SeekFrom, Cursor};
use std::collections::{HashMap, BTreeMap};
use std::ops::Range;

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
		ObjectFooterVirtual,
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
	ERROR_ZFFREADER_OPERATION_VIRTUAL_OBJECT,
	ERROR_MISSING_OBJECT_HEADER_IN_SEGMENT,
};

use super::*;

// - external
use redb::{Database, ReadableTable};

/// Defines the recognized object type (used by the [ZffReader]). 
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ObjectType {
	/// Physical object
	Physical,
	/// Logical object
	Logical,
	/// Virtual object,
	Virtual,
	/// Encrypted object (physical or logical)
	Encrypted,
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    	let value = match self {
    		ObjectType::Physical => "physical",
    		ObjectType::Logical => "logical",
    		ObjectType::Virtual => "virtual",
    		ObjectType::Encrypted => "encrypted",
    	};
        write!(f, "{value}")
    }
}

/// Several types of a preloaded chunkmap.
#[derive(Debug)]
pub enum PreloadedChunkMap {
	/// No chunkmap is preloaded.
	None,
	/// Contains a in-memory preloaded chunkmap.
	InMemory(HashMap<u64, u64>), //<Chunknumber, offset>,
	/// Contains a chunkmap, cached in the given Redb.
	Redb(Database),
}

/// The [ZffReader] can be used to read the data of a zff container in a proper way.  
/// It implements [std::io::Read] and [std::io::Seek] to ensure a wide range of possible use.
/// # Example
/// ```rust
/// use std::fs::File;
/// 
/// let segment_files = vec!["zff_segment.z01", "zff_segment.z02", "zff_segment.z03"];
/// let mut files = Vec::new();
/// for segment in segment_files {
///     files.push(File::open(segment).unwrap());
/// }
///
/// let zffreader = ZffReader::with_reader(files);
/// assert_eq!(zffreader.list_objects().unwrap().keys(), vec![1]);
/// // let us assume object 1 is a physical object.
/// zffreader.initialize_object(1).unwrap();
/// zffreader.set_active_object(1).unwrap();
/// 
/// let buffer = vec![0u8; 32000];
/// let _  = zffreader.read_exact(&mut buffer).unwrap();
/// ```
#[derive(Debug)]
pub struct ZffReader<R: Read + Seek> {
	segments: HashMap<u64, Segment<R>>, //<segment number, Segment>
	object_reader: HashMap<u64, ZffObjectReader>, //<object_number, ZffObjectReader>,
	main_footer: MainFooter,
	chunk_map: PreloadedChunkMap,
	active_object: u64, //the number of the active object.
}

impl<R: Read + Seek> ZffReader<R> {
	/// This method will initialize the [ZffReader] in general.  
	/// This method will identify the appropriate [SegmentHeader](crate::header::SegmentHeader), 
	/// [SegmentFooter](crate::footer::SegmentFooter) and [MainFooter](crate::footer::MainFooter).  
	/// This method will **not** initizalize the objects itself! This has to be done by using the
	/// initialize_object() or initialize_objects_all() methods.
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

	/// Lists all objects which are inside the zff container (even if they are uninitialized).
	/// Returns a BTreeMap, which contains the appropriate object number and the object type.
	/// # Error
	/// Fails if
	///   - a segment is missing which should contain the appropriate object header
	///   - there is a error while reading the object header
	///   - there is a decoding error (e.g. corrupted segment)
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

	///  Sets an appropriate object as active to read or seek from this object.
	///  # Error
	///  This method fails, if the appropriate object number not exists in this zff container.
	pub fn set_active_object(&mut self, object_number: u64) -> Result<()> {
		if self.object_reader.get(&object_number).is_some() {
			self.active_object = object_number;
			Ok(())
		} else {
			Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string()))
		}
	}

	///  Sets an appropriate file as active to read or seek from this object.
	///  # Error
	///  This method fails, if the appropriate object type is not "logical" or if no file for the appropriate file number exists.
	///  Will also fail, if no object was activated by using the set_active_object() method.
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

	/// Will initialize the appropriate object.
	/// # Error
	/// May fail due to various conditions, e.g. corrupted or missing segments.
	pub fn initialize_object(&mut self, object_number: u64) -> Result<()> {
		let object_reader = initialize_object_reader(object_number, &mut self.segments, &self.main_footer)?;
		self.object_reader.insert(object_number, object_reader);
		Ok(())
	}

	/// Same as initialize_object(), but will initialize **all** objects of this zff container.
	/// # Error
	/// May fail due to various conditions, e.g. corrupted or missing segments.
	pub fn initialize_objects_all(&mut self) -> Result<()> {
		let object_reader_map = initialize_object_reader_all(&mut self.segments, &self.main_footer)?;
		self.object_reader = object_reader_map;
		Ok(())
	}

	/// Lists the number of chunks of this zff container.
	pub fn number_of_chunks(&self) -> u64 {
		let (chunk_number, _) = self.main_footer.chunk_maps().last_key_value().unwrap_or((&0, &0));
		*chunk_number
	}

	/// Decrypts an encrypted initialized object (and re-initialize/replaces the appropriate object directly).
	/// # Error
	/// May fail due to various conditions:
	///   - The appropriate object number does not exist or is uninitialized.
	///   - The appropriate object is not encrypted.
	///   - The decryption password is incorrect.
	///   - The decoding or reading of the data fails (e.g. corrupted or missing segments)
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
			ZffObjectReader::Virtual(_) => ObjectType::Virtual,
			ZffObjectReader::Encrypted(_) => ObjectType::Encrypted,
		};
		self.object_reader.insert(object_number, decrypted_reader);
		Ok(o_type)
	}

	/// Defines a new preload chunkmap which will be held in memory, if none exists up to this point.
	/// This method will (then) only "initialize" a new preload chunkmap. You have to fill this map by using  
	/// methods like self::preloaded_chunkmap() or self::preload_chunkmap_full().  
	/// If there is already a preloaded chunkmap, then this method will
	///   - do nothing, if the existing preloaded chunkmap is an in-memory map.
	///   - convert the existing preloaded chunkmap to an in-memory chunkmap, if the existing preloaded chunkmap is a redb-based preloaded chunkmap.
	pub fn set_preload_chunkmap_mode_in_memory(&mut self) -> Result<()> {
		match &mut self.chunk_map {
			PreloadedChunkMap::None => self.chunk_map = PreloadedChunkMap::InMemory(HashMap::new()),
			PreloadedChunkMap::InMemory(_) => (),
			PreloadedChunkMap::Redb(ref mut db) => self.chunk_map = PreloadedChunkMap::InMemory(extract_redb_map(db)?),
		}
		Ok(())
	}

	/// Defines a new preload chunkmap which will be cached to a external Redb, if none exists up to this point.
	/// This method will (then) only "initialize" a new preload chunkmap. You have to fill this map by using  
	/// methods like self::preloaded_chunkmap() or self::preload_chunkmap_full().  
	/// If there is already a preloaded chunkmap, then this method will
	///   - Copy the content of the existing Redb to the new given Redb and use the given Redb as the new one.
	///   - Initialize a empty Redb and use this.
	///   - convert the existing preloaded (in-memory) chunkmap to the Redb (copy the content) and use the Redb as the appropriate preloaded chunkmap.
	pub fn set_preload_chunkmap_mode_redb(&mut self, mut db: Database) -> Result<()> {
		match &self.chunk_map {
			PreloadedChunkMap::Redb(old_db) => copy_redb_map(old_db, &mut db)?,
			PreloadedChunkMap::None => initialize_redb_chunkmap(&mut db, &HashMap::new())?,
			PreloadedChunkMap::InMemory(map) => initialize_redb_chunkmap(&mut db, map)?,
		}
		self.chunk_map = PreloadedChunkMap::Redb(db);
		Ok(())
	}
	
	/// Preloads the offsets of the given [Range](std::ops::Range) of chunks.
	/// If no chunkmap was initialized, a new in-memory map will be initialized by using this method.
	pub fn preload_chunkmap(&mut self, chunk_numbers: &Range<u64>) -> Result<()> {
		// check if chunk numbers are valid.
		if chunk_numbers.start == 0 {
			return Err(ZffError::new(ZffErrorKind::InvalidChunkNumber, chunk_numbers.start.to_string()));
		} else if chunk_numbers.start > chunk_numbers.end {
			return Err(ZffError::new(ZffErrorKind::InvalidChunkNumber, ERROR_LAST_GREATER_FIRST));
		} else if chunk_numbers.end > self.number_of_chunks() {
			return Err(ZffError::new(ZffErrorKind::InvalidChunkNumber, chunk_numbers.end.to_string()));	
		}

		//try to reserve the additional size, if PreloadedChunkMap::InMemory is used.
		let mut size = chunk_numbers.end - chunk_numbers.start;
		match &mut self.chunk_map {
			PreloadedChunkMap::None => {
				let mut map = HashMap::new();
				map.try_reserve(size as usize)?;
				self.chunk_map = PreloadedChunkMap::InMemory(map)
			},
			PreloadedChunkMap::Redb(_) => (),
			PreloadedChunkMap::InMemory(map) => {
				for chunk_no in chunk_numbers.start..=chunk_numbers.end {
					if map.contains_key(&chunk_no) {
						size -= 1;
					}
				}
				map.try_reserve(size as usize)?;
			}
		}

		for chunk_no in chunk_numbers.start..=chunk_numbers.end {
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

	/// Preloads all offsets of the chunks of the appropriate zff container.
	pub fn preload_chunkmap_full(&mut self) -> Result<()> {
		let first = 1;
		let last = self.number_of_chunks();
		self.preload_chunkmap(&Range{start: first, end: last})
	}

	/// Returns the [FileMetadata] of the appropriate active file.
	/// # Error
	/// May fail if   
	/// - the active object is not a "logical" object.  
	/// - the active file number was not set.  
	/// - no object was set as active.  
	pub fn current_filemetadata(&self) -> Result<&FileMetadata> {
		match self.object_reader.get(&self.active_object) {
			Some(ZffObjectReader::Logical(reader)) => {
				Ok(reader.filemetadata()?)
			},
			Some(ZffObjectReader::Physical(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_PHYSICAL_OBJECT)),
			Some(ZffObjectReader::Encrypted(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
			Some(ZffObjectReader::Virtual(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_VIRTUAL_OBJECT)),
			None => Err(ZffError::new(ZffErrorKind::MissingObjectNumber, self.active_object.to_string())),
		}
	}

	/// Returns the [FileHeader](crate::header::FileHeader) of the appropriate active file.
	/// # Error
	/// May fail if   
	/// - the active object is not a "logical" object.  
	/// - the active file number was not set.  
	/// - no object was set as active.  
	pub fn current_fileheader(&mut self) -> Result<FileHeader> {
		match self.object_reader.get(&self.active_object) {
			Some(ZffObjectReader::Logical(reader)) => {
				reader.current_fileheader(&mut self.segments)
			},
			Some(ZffObjectReader::Physical(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_PHYSICAL_OBJECT)),
			Some(ZffObjectReader::Encrypted(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
			Some(ZffObjectReader::Virtual(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_VIRTUAL_OBJECT)),
			None => Err(ZffError::new(ZffErrorKind::MissingObjectNumber, self.active_object.to_string())),
		}
	}

	/// Returns the [FileFooter](crate::footer::FileFooter) of the appropriate active file.
	/// # Error
	/// May fail if   
	/// - the active object is not a "logical" object.  
	/// - the active file number was not set.  
	/// - no object was set as active.  
	pub fn current_filefooter(&mut self) -> Result<FileFooter> {
		match self.object_reader.get(&self.active_object) {
			Some(ZffObjectReader::Logical(reader)) => {
				reader.current_filefooter(&mut self.segments)
			},
			Some(ZffObjectReader::Physical(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_PHYSICAL_OBJECT)),
			Some(ZffObjectReader::Encrypted(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
			Some(ZffObjectReader::Virtual(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_VIRTUAL_OBJECT)),
			None => Err(ZffError::new(ZffErrorKind::MissingObjectNumber, self.active_object.to_string())),
		}
	}

	/// Returns a reference to the [ObjectHeader](crate::header::ObjectHeader) of the appropriate active object.
	/// # Error
	/// May fail if   
	/// - no object was set as active.  
	/// - the object was not decrypted.
	pub fn active_object_header_ref(&self) -> Result<&ObjectHeader> {
		match self.get_active_reader()? {
			ZffObjectReader::Physical(reader) => Ok(reader.object_header_ref()),
			ZffObjectReader::Logical(reader) => Ok(reader.object_header_ref()),
			ZffObjectReader::Virtual(reader) => Ok(reader.object_header_ref()),
			ZffObjectReader::Encrypted(_) => Err(ZffError::new(ZffErrorKind::InvalidOption, ""))
		}
	}

	/// Returns the [ObjectFooter](crate::footer::ObjectFooter) of the appropriate active object.
	/// # Error
	/// May fail if   
	/// - no object was set as active.  
	/// - the object was not decrypted.
	pub fn active_object_footer(&self) -> Result<ObjectFooter> {
		match self.get_active_reader()? {
			ZffObjectReader::Physical(reader) => Ok(reader.object_footer()),
			ZffObjectReader::Logical(reader) => Ok(reader.object_footer()),
			ZffObjectReader::Virtual(reader) => Ok(reader.object_footer()),
			ZffObjectReader::Encrypted(_) => Err(ZffError::new(ZffErrorKind::InvalidOption, ""))
		}
	}

	fn get_active_reader(&self) -> Result<&ZffObjectReader> {
		match self.object_reader.get(&self.active_object) {
			Some(reader) => Ok(reader),
			None => Err(ZffError::new(ZffErrorKind::MissingObjectNumber, self.active_object.to_string())),
		}
	}

	/// Returns a reference to the [Segment](crate::segment::Segment) of the appropriate segment number.
	/// # Error
	/// May fail if   
	/// - the appropriate segment number does not exist.
	/// - a decoding error occurs while trying to read the appropriate metadata of the segment.
	pub fn segment_mut_ref(&mut self, segment_number: u64) -> Result<&mut Segment<R>> {
		match self.segments.get_mut(&segment_number) {
			Some(segment) => Ok(segment),
			None => Err(ZffError::new(ZffErrorKind::MissingSegment, segment_number.to_string()))
		}
	}
}

impl<R: Read + Seek> Read for ZffReader<R> {
	fn read(&mut self, buffer: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
		{
			let object_reader = match self.object_reader.get_mut(&self.active_object) {
				Some(object_reader) => object_reader,
				None => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{ERROR_ZFFREADER_MISSING_OBJECT}{}", self.active_object)))
			};
			match object_reader {
				ZffObjectReader::Physical(reader) => return reader.read_with_segments(buffer, &mut self.segments, &self.chunk_map),
				ZffObjectReader::Logical(reader) => return reader.read_with_segments(buffer, &mut self.segments, &self.chunk_map),
				ZffObjectReader::Encrypted(_) => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
				ZffObjectReader::Virtual(reader) => if !reader.is_passive_object_header_map_empty() { return reader.read_with_segments(buffer, &mut self.segments, &self.chunk_map); } else { () },
			}
		}

		// updates the object header map in virtual objects, if the map is empty (check see lines before: "is_passive_object_header_map_empty()").
		// this lines are moved at the end to ensure graciousness through the borrow checker.
		let mut passive_objects_map = BTreeMap::new();
		let passive_objects_vec = match self.object_reader.get(&self.active_object) {
			Some(object_reader) => match object_reader {
				ZffObjectReader::Virtual(reader) => reader.object_footer_ref().passive_objects.clone(),
				_ => unreachable!(),
			},
			None => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{ERROR_ZFFREADER_MISSING_OBJECT}{}", self.active_object)))
		};
		for passive_object_no in passive_objects_vec {
			let object_header = match self.object_reader.get(&passive_object_no) {
				Some(reader) => match reader {
					ZffObjectReader::Physical(phy) => phy.object_header_ref(),
					ZffObjectReader::Logical(log) => log.object_header_ref(),
					ZffObjectReader::Virtual(_) => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_VIRTUAL_OBJECT)),
					ZffObjectReader::Encrypted(_) => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
				},
				None => return Err(
					std::io::Error::new(
						std::io::ErrorKind::NotFound, 
						format!("{ERROR_MISSING_OBJECT_HEADER_IN_SEGMENT}{passive_object_no}"))
				),
			};
			passive_objects_map.insert(passive_object_no, object_header.clone());
		}
		let object_reader = match self.object_reader.get_mut(&self.active_object) {
			Some(object_reader) => object_reader,
			None => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{ERROR_ZFFREADER_MISSING_OBJECT}{}", self.active_object)))
		};
		match object_reader {
			ZffObjectReader::Virtual(reader) => { 
				reader.update_passive_object_header_map(passive_objects_map); 
				reader.read_with_segments(buffer, &mut self.segments, &self.chunk_map)
			},
			_ => unreachable!(),
		}		
	}
}

/*
{
	// fill the passive object header map while first read operation.
	if reader.is_passive_object_header_map_empty() {
		let mut passive_objects = BTreeMap::new();
		for passive_object_no in &reader.object_footer_ref().passive_objects {
			let object_header = match self.object_reader.get(&passive_object_no) {
				Some(reader) => match reader {
					ZffObjectReader::Physical(phy) => phy.object_header_ref(),
					ZffObjectReader::Logical(log) => log.object_header_ref(),
					ZffObjectReader::Virtual(_) => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_VIRTUAL_OBJECT)),
					ZffObjectReader::Encrypted(_) => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
				},
				None => return Err(
					std::io::Error::new(
						std::io::ErrorKind::NotFound, 
						format!("{ERROR_MISSING_OBJECT_HEADER_IN_SEGMENT}{passive_object_no}"))
				),
			};
			passive_objects.insert(*passive_object_no, object_header.clone());
		}
		reader.update_passive_object_header_map(passive_objects);
	}
},
*/

impl<R: Read + Seek> Seek for ZffReader<R> {
	fn seek(&mut self, seek_from: SeekFrom) -> std::result::Result<u64, std::io::Error> {
		let object_reader = match self.object_reader.get_mut(&self.active_object) {
			Some(object_reader) => object_reader,
			None => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{ERROR_ZFFREADER_MISSING_OBJECT}{}", self.active_object)))
		};
		object_reader.seek(seek_from)
	}
}

/// An enum, which provides an appropriate object reader.
#[derive(Debug)]
pub(crate) enum ZffObjectReader {
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
	global_chunkmap: BTreeMap<u64, u64>,
	position: u64
}

impl ZffObjectReaderPhysical {
	/// creates a new [ZffObjectReaderPhysical] with the given metadata.
	pub fn with_obj_metadata(
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
	global_chunkmap: BTreeMap<u64, u64>, //TODO: only used in read_with_segments. Could also be a &-paramter for the specific method?
	active_file: u64, // filenumber of active file
	files: HashMap<u64, FileMetadata>//<filenumber, metadata>
}

impl ZffObjectReaderLogical {
	/// Initialize the [ZffObjectReaderLogical] with a minimal set of (the absolutly required) metadata which will be stored in memory.
	pub fn with_obj_metadata_minimal<R: Read + Seek>(
		object_header: ObjectHeader, 
		object_footer: ObjectFooterLogical,
		segments: &mut HashMap<u64, Segment<R>>, //<segment number, Segment-object>
		global_chunkmap: BTreeMap<u64, u64>,
		) -> Result<Self> {
		Self::with_obj_metadata(object_header, object_footer, segments, global_chunkmap, PreloadDegree::Minimal)
	}

	/// Initialize the [ZffObjectReaderLogical] with the recommended set of metadata which will be stored in memory.
	pub fn with_obj_metadata_recommended<R: Read + Seek>(
		object_header: ObjectHeader, 
		object_footer: ObjectFooterLogical,
		segments: &mut HashMap<u64, Segment<R>>, //<segment number, Segment-object>
		global_chunkmap: BTreeMap<u64, u64>,
		) -> Result<Self> {
		Self::with_obj_metadata(object_header, object_footer, segments, global_chunkmap, PreloadDegree::Recommended)
	}

	/// Initialize the [ZffObjectReaderLogical] which will store all metadata in memory.
	pub fn with_obj_metadata_all<R: Read + Seek>(
		object_header: ObjectHeader, 
		object_footer: ObjectFooterLogical,
		segments: &mut HashMap<u64, Segment<R>>, //<segment number, Segment-object>
		global_chunkmap: BTreeMap<u64, u64>,
		) -> Result<Self> {
		Self::with_obj_metadata(object_header, object_footer, segments, global_chunkmap, PreloadDegree::All)
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

	fn filemetadata(&self) -> Result<&FileMetadata> {
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
pub(crate) struct ZffObjectReaderVirtual {
	/// Contains the appropriate object header
	object_header: ObjectHeader,
	/// Contains the appropriate object footer of the virtual object
	object_footer: ObjectFooterVirtual,
	/// Cached header of all affected passive objects.
	passive_object_header: BTreeMap<u64, ObjectHeader>,
	/// Preloaded offset map (optional)
	preloaded_offset_map: BTreeMap<u64, u64>,
	/// The global chunkmap which could be found in the [crate::footer::MainFooter].
	global_chunkmap: BTreeMap<u64, u64>, //TODO: only used in read_with_segments. Could also be a &-paramter for the specific method?
	/// the internal reader position
	position: u64,
}

impl ZffObjectReaderVirtual {
	pub(crate) fn with_data(
		object_header: ObjectHeader,
		object_footer: ObjectFooterVirtual,
		global_chunkmap: BTreeMap<u64, u64>) -> Self {
		Self {
			object_header,
			object_footer,
			passive_object_header: BTreeMap::new(),
			preloaded_offset_map: BTreeMap::new(),
			global_chunkmap,
			position: 0
		}
	}

	pub(crate) fn is_passive_object_header_map_empty(&self) -> bool {
		self.passive_object_header.is_empty()
	}

	pub(crate) fn update_passive_object_header_map(&mut self, passive_object_header: BTreeMap<u64, ObjectHeader>) {
		self.passive_object_header = passive_object_header;
	}

	/// Returns a reference of the appropriate [ObjectHeader](crate::header::ObjectHeader).
	pub(crate) fn object_header_ref(&self) -> &ObjectHeader {
		&self.object_header
	}

	pub(crate) fn object_footer_ref(&self) -> &ObjectFooterVirtual {
		&self.object_footer
	}

	/// Returns the appropriate [ObjectFooter](crate::footer::ObjectFooter).
	pub(crate) fn object_footer(&self) -> ObjectFooter {
		ObjectFooter::Virtual(self.object_footer.clone())
	}

	/// Works like [std::io::Read] for the underlying data, but needs also the segments and the optional preloaded chunkmap.  
	pub(crate) fn read_with_segments<R: Read + Seek>(
		&mut self, 
		_buffer: &mut [u8], 
		_segments: &mut HashMap<u64, Segment<R>>,
		_preloaded_chunkmap: &PreloadedChunkMap,
		) -> std::result::Result<usize, std::io::Error> {

		let _ = self.preloaded_offset_map;
		let _ = self.global_chunkmap;
		todo!()
	}
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
			ObjectFooter::Virtual(virt) => ZffObjectReader::Virtual(Box::new(
				ZffObjectReaderVirtual::with_data(decrypted_object_header, virt, global_chunkmap.clone())))
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
	pub metadata_ext: HashMap<String, String>,
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
	chunk_offset: Option<u64>,
	) -> std::result::Result<Vec<u8>, std::io::Error>
where
	C: Borrow<CompressionAlgorithm> + std::marker::Copy,
	R: Read + Seek
{
	let chunk_content = match segment.chunk_data(current_chunk_number, enc_information, compression_algorithm, chunk_offset) {
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
			get_chunk_data(segment, dup_chunk_no, enc_information, compression_algorithm, chunk_size, chunk_offset)
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
		ObjectFooter::Virtual(virt) => ZffObjectReader::Virtual(Box::new(ZffObjectReaderVirtual::with_data(header, virt, main_footer.chunk_maps().clone()))),
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

// Will copy a redb to another redb.
fn copy_redb_map(input_db: &Database, output_db: &mut Database) -> Result<()> {
	// prepare read context of input_db
	let read_txn = input_db.begin_read()?;
	let read_table = read_txn.open_table(PRELOADED_CHUNK_MAP_TABLE)?;
	let mut table_iterator = read_table.iter()?;

	// prepare write context of output_db
	let write_txn = output_db.begin_write()?;
	let mut write_table = write_txn.open_table(PRELOADED_CHUNK_MAP_TABLE)?;

	while let Some(data) = table_iterator.next_back() {
		let (key, value) = data?;
		write_table.insert(key.value(), value.value())?;
	}
	Ok(())
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

// tries to extract the appropriate offset of the given chunk number.
// returns a None in case of error or if the chunkmap is a [PreloadedChunkmap::None].
fn extract_offset_from_preloaded_chunkmap(preloaded_chunkmap: &PreloadedChunkMap, chunk_number: u64) -> Option<u64> {
	match preloaded_chunkmap {
		PreloadedChunkMap::None => None,
		PreloadedChunkMap::InMemory(map) => map.get(&chunk_number).copied(),
		PreloadedChunkMap::Redb(db) => {
			let read_txn = db.begin_read().ok()?;
    		let table = read_txn.open_table(PRELOADED_CHUNK_MAP_TABLE).ok()?;
    		let value = table.get(&chunk_number).ok()??.value();
    		Some(value)
		}
	}
}