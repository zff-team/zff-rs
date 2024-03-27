// - STD
use std::fmt;
use std::borrow::Borrow;
use std::io::{Read, Seek, SeekFrom};
use std::collections::{HashMap, BTreeMap};
use std::ops::Range;

// - modules
mod zffobjectreader;

// - re-exports
pub use zffobjectreader::*;

// - internal
use crate::{
	Segment,
	HeaderCoding,
	ValueDecoder,
	footer::{
		MainFooter,
		FileFooter,
		SegmentFooter,
		ObjectFooter,
	},
	helper::get_segment_of_chunk_no,
	header::{EncryptionInformation, SegmentHeader, ObjectType as HeaderObjectType},
	ChunkContent,
};

use super::*;

// - external
use redb::{Database, ReadableTable};

#[cfg(feature = "log")]
use log::debug;

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
/// ```no_run
/// use zff::io::zffreader::ZffReader;
/// use std::fs::File;
/// use std::io::Read;
/// 
/// let segment_files = vec!["zff_segment.z01", "zff_segment.z02", "zff_segment.z03"];
/// let mut files = Vec::new();
/// for segment in segment_files {
///     files.push(File::open(segment).unwrap());
/// }
///
/// let mut zffreader = ZffReader::with_reader(files).unwrap();
/// // list available object numbers.
/// println!("{:?}", zffreader.list_objects().unwrap().keys());
/// // let us assume object 1 is a physical object.
/// zffreader.initialize_object(1).unwrap();
/// zffreader.set_active_object(1).unwrap();
/// 
/// let mut buffer = vec![0u8; 32000];
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
		#[cfg(feature = "log")]
		debug!("Initialize ZffReader with {} segments.", reader_vec.len());

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
		if self.object_reader.contains_key(&object_number) {
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
				_ => Err(ZffError::new(ZffErrorKind::MismatchObjectType, self.active_object.to_string()))
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
			ZffObjectReader::Encrypted(reader) => reader.decrypt_with_password(decryption_password, &mut self.segments)?,
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
					None => return Err(ZffError::new(
						ZffErrorKind::MissingSegment, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
				},
				None => return Err(ZffError::new(
					ZffErrorKind::InvalidChunkNumber, chunk_no.to_string())),
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
				ZffObjectReader::Physical(reader) => return reader.read_with_segments(buffer, &mut self.segments, &self.chunk_map, &self.main_footer.chunk_maps),
				ZffObjectReader::Logical(reader) => return reader.read_with_segments(buffer, &mut self.segments, &self.chunk_map, &self.main_footer.chunk_maps),
				ZffObjectReader::Encrypted(_) => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
				ZffObjectReader::Virtual(reader) => if !reader.is_passive_object_header_map_empty() { return reader.read_with_segments(buffer, &mut self.segments, &self.chunk_map, &self.main_footer.chunk_maps); },
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
				reader.read_with_segments(buffer, &mut self.segments, &self.chunk_map, &self.main_footer.chunk_maps)
			},
			_ => unreachable!(),
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

fn extract_recommended_metadata(fileheader: &FileHeader) -> HashMap<String, MetadataExtendedValue> {
	let mut metadata = HashMap::new();
	if let Some(value) = fileheader.metadata_ext.get(METADATA_ATIME) {
		metadata.insert(METADATA_ATIME.to_string(), value.clone());
	}
	if let Some(value) = fileheader.metadata_ext.get(METADATA_MTIME) {
		metadata.insert(METADATA_MTIME.to_string(), value.clone());
	}
	if let Some(value) = fileheader.metadata_ext.get(METADATA_CTIME) {
		metadata.insert(METADATA_CTIME.to_string(), value.clone());
	}
	if let Some(value) = fileheader.metadata_ext.get(METADATA_BTIME) {
		metadata.insert(METADATA_BTIME.to_string(), value.clone());
	}

	#[cfg(target_family = "unix")]
	if let Some(value) = fileheader.metadata_ext.get(METADATA_EXT_KEY_UID) {
		metadata.insert(METADATA_EXT_KEY_UID.to_string(), value.clone());
	}
	#[cfg(target_family = "unix")]
	if let Some(value) = fileheader.metadata_ext.get(METADATA_EXT_KEY_GID) {
		metadata.insert(METADATA_EXT_KEY_GID.to_string(), value.clone());
	}
	#[cfg(target_family = "unix")]
	if let Some(value) = fileheader.metadata_ext.get(METADATA_EXT_KEY_MODE) {
		metadata.insert(METADATA_EXT_KEY_MODE.to_string(), value.clone());
	}

	metadata
}

fn extract_all_metadata(fileheader: &FileHeader) -> HashMap<String, MetadataExtendedValue> {
	fileheader.metadata_ext.clone()
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
								segments)
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
	) -> Result<ZffObjectReader> {
	#[cfg(feature = "log")]
	debug!("Initialize unencrypted object reader for object {}", obj_number);

	let header = match segments.get_mut(&header_segment_no) {
		None => return Err(ZffError::new(ZffErrorKind::MissingSegment, header_segment_no.to_string())),
		Some(segment) => segment.read_object_header(obj_number)?,
	};

	let footer = match segments.get_mut(&footer_segment_no) {
		None => return Err(ZffError::new(ZffErrorKind::MissingSegment, header_segment_no.to_string())),
		Some(segment) => segment.read_object_footer(obj_number)?,
	};

	let obj_reader = match footer {
		ObjectFooter::Physical(physical) => ZffObjectReader::Physical(Box::new(ZffObjectReaderPhysical::with_obj_metadata(header, physical))),
		ObjectFooter::Logical(logical) => ZffObjectReader::Logical(Box::new(ZffObjectReaderLogical::with_obj_metadata_recommended(header, logical, segments)?)),
		ObjectFooter::Virtual(virt) => ZffObjectReader::Virtual(Box::new(ZffObjectReaderVirtual::with_data(header, virt))),
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