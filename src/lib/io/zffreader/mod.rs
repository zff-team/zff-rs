// - STD
use std::fmt;
use std::io::{Read, Seek, SeekFrom};
use std::collections::{HashMap, BTreeMap};
use std::sync::{Arc, Mutex};

// - modules
mod zffobjectreader;
mod redb_handling;

// - re-exports
pub use zffobjectreader::*;
pub(crate) use redb_handling::*;

// - internal
use crate::{
	Segment,
	HeaderCoding,
	ValueDecoder,
	footer::{
		FileFooter,
		SegmentFooter,
		ObjectFooter,
	},
	helper::get_segment_of_chunk_no,
	header::{
		EncryptionInformation, 
		SegmentHeader, 
		ObjectType as HeaderObjectType,
		ChunkFlags,
		ChunkOffsetMap,
		ChunkSizeMap,
		ChunkFlagsMap,
		ChunkXxHashMap,
		ChunkSamebytesMap,
		ChunkDeduplicationMap,
		ChunkMap,
	},
	ChunkContent,
};

use super::*;

// - type definitions
// This is a Arc instead of a Rc to optain more flexibility by using the [ZffReader] 
// (Rc / RefCell do not implement Send :-( )).
type ArcZffReaderMetadata<R> = Arc<Mutex<ZffReaderGeneralMetadata<R>>>;

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

/// The preloaded chunkmaps which can be used by the [ZffReader] to speed up the reading process.
#[derive(Debug, Default)]
pub(crate) struct PreloadedChunkMapsInMemory {
	offsets: HashMap<u64, u64>,
	sizes: HashMap<u64, u64>,
	flags: HashMap<u64, ChunkFlags>,
	xxhashs: HashMap<u64, u64>,
	same_bytes: HashMap<u64, u8>,
	duplicate_chunks: HashMap<u64, u64>,
}

impl PreloadedChunkMapsInMemory {
	pub fn with_data(offsets: HashMap<u64, u64>, 
		sizes: HashMap<u64, u64>, 
		flags: HashMap<u64, ChunkFlags>, 
		xxhashs: HashMap<u64, u64>, 
		same_bytes: HashMap<u64, u8>, 
		duplicate_chunks: HashMap<u64, u64>
	) -> Self {
		Self {
			offsets,
			sizes,
			flags,
			xxhashs,
			same_bytes,
			duplicate_chunks,
		}
	}
}

/// The preloaded chunkmaps which can be used by the [ZffReader] to speed up the reading process.
#[derive(Debug, Default)]
pub(crate) enum PreloadedChunkMaps {
	#[default]
	None,
	InMemory(PreloadedChunkMapsInMemory),
	Redb(Database),
}

impl PreloadedChunkMaps {
	/// Defines a new preload chunkmap which will be held in memory, if none exists up to this point.
	/// This method will (then) only "initialize" a new preload chunkmap. You have to fill this map by using  
	/// methods like self::preloaded_chunkmap() or self::preload_chunkmap_full().  
	/// If there is already a preloaded chunkmap, then this method will
	///   - do nothing, if the existing preloaded chunkmap is an in-memory map.
	///   - convert the existing preloaded chunkmap to an in-memory chunkmap, if the existing preloaded chunkmap is a redb-based preloaded chunkmap.
	fn set_mode_in_memory(&mut self) -> Result<()> {
		match self {
			PreloadedChunkMaps::None => *self = PreloadedChunkMaps::InMemory(PreloadedChunkMapsInMemory::default()),
			PreloadedChunkMaps::InMemory(_) => (),
			PreloadedChunkMaps::Redb(ref mut db) => *self = PreloadedChunkMaps::InMemory(convert_redb_into_in_memory_preloaded_chunkmaps(db)?),
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
	fn set_mode_redb(&mut self, mut db: Database) -> Result<()> {
		match self {
			PreloadedChunkMaps::None => *self = PreloadedChunkMaps::Redb(db),
			PreloadedChunkMaps::InMemory(map) => convert_in_memory_preloaded_chunkmaps_into_redb(&mut db, map)?,
			PreloadedChunkMaps::Redb(old_db) => {
				copy_redb(old_db, &mut db)?;
				*self = PreloadedChunkMaps::Redb(db);
			},
		};
		Ok(())
	}

	fn get_samebyte(&self, chunk_no: u64) -> Option<u8> {
		extract_samebyte_from_preloaded_chunkmap(&self, chunk_no)
	}
}

/// internally handled metadata for the [ZffReader] (and appropriate [ZffObjectReader])
#[derive(Debug)]
pub(crate) struct ZffReaderGeneralMetadata<R: Read + Seek> {
	pub segments: HashMap<u64, Segment<R>>, //<segment number, Segment>
	pub object_metadata: BTreeMap<u64, ObjectMetadata>, //<object number, ObjectMetadata>
	pub main_footer: MainFooter,
	pub preloaded_chunkmaps: PreloadedChunkMaps,
}

impl<R: Read + Seek> ZffReaderGeneralMetadata<R> {
	fn new(segments: HashMap<u64, Segment<R>>, main_footer: MainFooter) -> Self {
		Self {
			segments,
			object_metadata: BTreeMap::new(),
			main_footer,
			preloaded_chunkmaps: PreloadedChunkMaps::default(),
		}
	}

	/// Returns a reference of the appropriate [ObjectHeader](crate::header::ObjectHeader) to the given Object number.
	pub fn object_header_ref(&self, object_no: &u64) -> Option<&ObjectHeader> {
		Some(&self.object_metadata.get(object_no)?.header)
	}

	/// Returns a Clone of the appropriate [ObjectHeader](crate::header::ObjectHeader) to the given Object number.
	pub fn object_header(&self, object_no: &u64) -> Option<ObjectHeader> {
		Some(self.object_metadata.get(object_no)?.header.clone())
	}

	/// Returns a Clone of the appropriate [ObjectFooter](crate::header::ObjectFooter) to the given Object number.
	pub fn object_footer(&self, object_no: &u64) -> Option<ObjectFooter> {
		Some(self.object_metadata.get(object_no)?.footer.clone())
	}
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
	metadata: ArcZffReaderMetadata<R>,
	object_reader: HashMap<u64, ZffObjectReader<R>>, //<object_number, ZffObjectReader>,
	active_object: u64, //the number of the active object.
}

impl<R: Read + Seek> ZffReader<R> {
	/// This method will initialize the [ZffReader] in general.  
	/// This method will identify the appropriate [SegmentHeader], 
	/// [SegmentFooter] and [MainFooter].  
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

		let metadata = Arc::new(Mutex::new(ZffReaderGeneralMetadata::new(segments, main_footer)));

		Ok(Self {
			metadata,
			object_reader: HashMap::new(),
			active_object: 0,
		})
	}

	/// Lists all objects which are inside the zff container (even if they are uninitialized).
	/// Returns a BTreeMap, which contains the appropriate object number and the object type.
	/// # Error
	/// Fails if
	///   - a segment is missing which should contain the appropriate object header
	///   - there is an error while reading the object header
	///   - there is a decoding error (e.g. corrupted segment)
	pub fn list_objects(&mut self) -> Result<BTreeMap<u64, ObjectType>> {
		let mut map = BTreeMap::new();
		let segments = &mut self.metadata.lock().unwrap().segments;
		for (object_number, segment_number) in self.metadata.lock().unwrap().main_footer.object_header() {
			let segment = match segments.get_mut(segment_number) {
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

	/// Same as list_objects, but ignores encrypted objects
	pub fn list_decrypted_objects(&self) -> BTreeMap<u64, ObjectType> {
		let mut map = BTreeMap::new();
		for (k, v) in &self.object_reader {
			match v {
				ZffObjectReader::Encrypted(_) => (),
				ZffObjectReader::Physical(_) => { map.insert(*k, ObjectType::Physical); },
				ZffObjectReader::Logical(_) => { map.insert(*k, ObjectType::Logical); },
				ZffObjectReader::Virtual(_) => { map.insert(*k, ObjectType::Virtual); },
			};
		};
		map
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
		let object_reader = initialize_object_reader(object_number, Arc::clone(&self.metadata))?;
		self.object_reader.insert(object_number, object_reader);
		Ok(())
	}

	/// Same as initialize_object(), but will initialize **all** objects of this zff container.
	/// # Error
	/// May fail due to various conditions, e.g. corrupted or missing segments.
	pub fn initialize_objects_all(&mut self) -> Result<()> {
		let object_reader_map = initialize_object_reader_all(Arc::clone(&self.metadata))?;
		self.object_reader = object_reader_map;
		Ok(())
	}

	/// Lists the number of chunks of this zff container.
	pub fn number_of_chunks(&self) -> u64 {
		let metadata = self.metadata.lock().unwrap();
		let (chunk_number, _) = metadata.main_footer.chunk_offset_maps().last_key_value().unwrap_or((&0, &0));
		*chunk_number
	}

	/// Returns the Data of the given chunk no
	/// # Error
	/// - If the object is encrypted, it will return an error.
	/// - If the chunk number is out of range, it will return an error.
	pub fn chunk_data(&self, chunk_no: u64) -> Result<Vec<u8>> {
		//TODO
		unimplemented!()
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
			ZffObjectReader::Encrypted(reader) => reader.decrypt_with_password(decryption_password)?,
			_ => return Err(ZffError::new(ZffErrorKind::NoEncryptionDetected, object_number.to_string()))
		};
		let o_type = match decrypted_reader {
			ZffObjectReader::Physical(_) => ObjectType::Physical,
			ZffObjectReader::Logical(_) => ObjectType::Logical,
			ZffObjectReader::Virtual(_) => ObjectType::Virtual,
			ZffObjectReader::Encrypted(_) => ObjectType::Encrypted,
		};
		self.object_reader.insert(object_number, decrypted_reader);

		// auto-preload chunkmaps for performance reasons
		self.auto_preload_object_maps(object_number)?;

		Ok(o_type)
	}

	/// Defines a new preload chunkmap which will be held in memory, if none exists up to this point.
	/// This method will (then) only "initialize" a new preload chunkmap. You have to fill this map by using  
	/// methods like self::preloaded_chunkmap() or self::preload_chunkmap_full().  
	/// If there is already a preloaded chunkmap, then this method will
	///   - do nothing, if the existing preloaded chunkmap is an in-memory map.
	///   - convert the existing preloaded chunkmap to an in-memory chunkmap, if the existing preloaded chunkmap is a redb-based preloaded chunkmap.
	pub fn set_preload_chunkmaps_mode_in_memory(&mut self) -> Result<()> {
		self.metadata.lock().unwrap().preloaded_chunkmaps.set_mode_in_memory()?;
		Ok(())
	}

	/// Defines a new preload chunkmap which will be cached to a external Redb, if none exists up to this point.
	/// This method will (then) only "initialize" a new preload chunkmap. You have to fill this map by using  
	/// methods like self::preloaded_chunkmap() or self::preload_chunkmap_full().  
	/// If there is already a preloaded chunkmap, then this method will
	///   - Copy the content of the existing Redb to the new given Redb and use the given Redb as the new one.
	///   - Initialize a empty Redb and use this.
	///   - convert the existing preloaded (in-memory) chunkmap to the Redb (copy the content) and use the Redb as the appropriate preloaded chunkmap.
	pub fn set_preload_chunkmap_mode_redb(&mut self, db: Database) -> Result<()> {
		self.metadata.lock().unwrap().preloaded_chunkmaps.set_mode_redb(db)
	}

	/// Automatically preloads all maps of the specific object (will be used in case of encrypted maps for performance reasons).
	fn auto_preload_object_maps(&mut self, object_number: u64) -> Result<()> {
		self.preload_chunk_offset_map_per_object(object_number)?;
		self.preload_chunk_size_map_per_object(object_number)?;
		self.preload_chunk_flags_map_per_object(object_number)?;
		self.preload_chunk_samebytes_map_per_object(object_number)?;
		self.preload_chunk_deduplication_map_per_object(object_number)?;
		Ok(())
	}

	/// Preloads the chunk offset map of the given highest chunk number of the map.
	/// If no chunkmap was initialized, a new in-memory map will be initialized by using this method.
	fn preload_chunk_offset_map(&mut self, chunk_number: u64, encryption_information: &Option<EncryptionInformation>) -> Result<()> {
		let segments = &mut self.metadata.lock().unwrap().segments;
		for segment in segments.values_mut() {
			if let Some(offset) = segment.footer().chunk_offset_map_table.get(&chunk_number) {
				segment.seek(SeekFrom::Start(*offset))?;
				let mut map = if let Some(ref enc_info) = encryption_information {
					ChunkOffsetMap::decrypt_and_decode(
						&enc_info.encryption_key, &enc_info.algorithm, segment, chunk_number)?
				} else {
					ChunkOffsetMap::decode_directly(segment)?
				};
				let inner_map = map.flush();
				
				let borrowed_metadata = &mut self.metadata.lock().unwrap();
				match borrowed_metadata.preloaded_chunkmaps {
					PreloadedChunkMaps::None => initialize_new_map_if_empty(Arc::clone(&self.metadata)),
					PreloadedChunkMaps::InMemory(ref mut maps) => maps.offsets.extend(inner_map),
					PreloadedChunkMaps::Redb(ref mut db) => {
						for (chunk_no, value) in inner_map {
							preloaded_redb_chunk_offset_map_add_entry(db, chunk_no, value)?;
						}
					}
				}
			}				
		}

		Ok(())
	}

	/// Preloads all chunk offset maps for the specific object.
	pub fn preload_chunk_offset_map_per_object(&mut self, object_number: u64) -> Result<()> {
		initialize_new_map_if_empty(Arc::clone(&self.metadata));
		
		#[cfg(feature = "log")]
		log::debug!("Preloading chunk offset map for object {}", object_number);
		let obj_reader = match self.object_reader.get(&object_number) {
			Some(reader) => reader,
			None => return Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string())),
		};
		let chunk_numbers = get_chunks_of_unencrypted_object(&self.object_reader, object_number)?;
		let enc_info = get_enc_info_from_obj_reader(obj_reader)?;
		for chunk_no in chunk_numbers {
			self.preload_chunk_offset_map(chunk_no, &enc_info)?;
		}
		Ok(())
	}

	/// Preloads all chunk offset maps for all objects.
	pub fn preload_chunk_offset_map_full(&mut self) -> Result<()> {
		let obj_numbers = self.unencrypted_object_no();
		for obj_no in obj_numbers {
			self.preload_chunk_offset_map_per_object(obj_no)?;
		}

		Ok(())
	}

	/// Preloads the chunk size map of the given highest chunk number of the map.
	/// If no chunkmap was initialized, a new in-memory map will be initialized by using this method.
	fn preload_chunk_size_map(&mut self, chunk_number: u64, encryption_information: &Option<EncryptionInformation>) -> Result<()> {
		let segments = &mut self.metadata.lock().unwrap().segments;
		for segment in segments.values_mut() {
			if let Some(offset) = segment.footer().chunk_size_map_table.get(&chunk_number) {
				segment.seek(SeekFrom::Start(*offset))?;
				let mut map = if let Some(ref enc_info) = encryption_information {
					ChunkSizeMap::decrypt_and_decode(
						&enc_info.encryption_key, &enc_info.algorithm, segment, chunk_number)?
				} else {
					ChunkSizeMap::decode_directly(segment)?
				};
				let inner_map = map.flush();
				
				let borrowed_metadata = &mut self.metadata.lock().unwrap();
				match borrowed_metadata.preloaded_chunkmaps {
					PreloadedChunkMaps::None => initialize_new_map_if_empty(Arc::clone(&self.metadata)),
					PreloadedChunkMaps::InMemory(ref mut maps) => maps.sizes.extend(inner_map),
					PreloadedChunkMaps::Redb(ref mut db) => {
						for (chunk_no, value) in inner_map {
							preloaded_redb_chunk_size_map_add_entry(db, chunk_no, value)?;
						}
					}
				}
			}				
		}

		Ok(())
	}

	/// Preloads all chunk size maps for the specific object.
	pub fn preload_chunk_size_map_per_object(&mut self, object_number: u64) -> Result<()> {
		initialize_new_map_if_empty(Arc::clone(&self.metadata));

		#[cfg(feature = "log")]
		log::debug!("Preloading chunk size map for object {}", object_number);
		let obj_reader = match self.object_reader.get(&object_number) {
			Some(reader) => reader,
			None => return Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string())),
		};

		let chunk_numbers = get_chunks_of_unencrypted_object(&self.object_reader, object_number)?;
		let enc_info = get_enc_info_from_obj_reader(obj_reader)?;

		for chunk_no in chunk_numbers {
			self.preload_chunk_size_map(chunk_no, &enc_info)?;
		}
		Ok(())
	}

	/// Preloads all chunk size maps for all objects.
	pub fn preload_chunk_size_map_full(&mut self) -> Result<()> {
		let obj_numbers = self.unencrypted_object_no();
		for obj_no in obj_numbers {
			self.preload_chunk_size_map_per_object(obj_no)?;
		}

		Ok(())
	}

	/// Preloads the chunk flags map of the given highest chunk number of the map.
	/// If no chunkmap was initialized, a new in-memory map will be initialized by using this method.
	fn preload_chunk_flags_map(&mut self, chunk_number: u64, encryption_information: &Option<EncryptionInformation>) -> Result<()> {
		let segments = &mut self.metadata.lock().unwrap().segments;
		for segment in segments.values_mut() {
			if let Some(offset) = segment.footer().chunk_flags_map_table.get(&chunk_number) {
				segment.seek(SeekFrom::Start(*offset))?;
				let mut map = if let Some(ref enc_info) = encryption_information {
					ChunkFlagsMap::decrypt_and_decode(
						&enc_info.encryption_key, &enc_info.algorithm, segment, chunk_number)?
				} else {
					ChunkFlagsMap::decode_directly(segment)?
				};
				let inner_map = map.flush();
				
				let borrowed_metadata = &mut self.metadata.lock().unwrap();
				match borrowed_metadata.preloaded_chunkmaps {
					PreloadedChunkMaps::None => initialize_new_map_if_empty(Arc::clone(&self.metadata)),
					PreloadedChunkMaps::InMemory(ref mut maps) => maps.flags.extend(inner_map),
					PreloadedChunkMaps::Redb(ref mut db) => {
						for (chunk_no, value) in inner_map {
							preloaded_redb_chunk_flags_map_add_entry(db, chunk_no, value)?;
						}
					}
				}
			}				
		}

		Ok(())
	}

	/// Preloads all chunk flags maps for the specific object.
	pub fn preload_chunk_flags_map_per_object(&mut self, object_number: u64) -> Result<()> {
		initialize_new_map_if_empty(Arc::clone(&self.metadata));

		#[cfg(feature = "log")]
		log::debug!("Preloading chunk flags map for object {}", object_number);
		let obj_reader = match self.object_reader.get(&object_number) {
			Some(reader) => reader,
			None => return Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string())),
		};

		let chunk_numbers = get_chunks_of_unencrypted_object(&self.object_reader, object_number)?;
		let enc_info = get_enc_info_from_obj_reader(obj_reader)?;

		for chunk_no in chunk_numbers {
			self.preload_chunk_flags_map(chunk_no, &enc_info)?;
		}
		Ok(())
	}

	/// Preloads all chunk flags maps for all objects.
	pub fn preload_chunk_flags_map_full(&mut self) -> Result<()> {
		let obj_numbers = self.unencrypted_object_no();
		for obj_no in obj_numbers {
			self.preload_chunk_flags_map_per_object(obj_no)?;
		}

		Ok(())
	}

	/// Preloads the chunk xxhash map of the given highest chunk number of the map.
	/// If no chunkmap was initialized, a new in-memory map will be initialized by using this method.
	fn preload_chunk_xxhash_map(&mut self, chunk_number: u64, encryption_information: &Option<EncryptionInformation>) -> Result<()> {
		let segments = &mut self.metadata.lock().unwrap().segments;
		for segment in segments.values_mut() {
			if let Some(offset) = segment.footer().chunk_xxhash_map_table.get(&chunk_number) {
				segment.seek(SeekFrom::Start(*offset))?;
				let mut map = if let Some(ref enc_info) = encryption_information {
					ChunkXxHashMap::decrypt_and_decode(
						&enc_info.encryption_key, &enc_info.algorithm, segment, chunk_number)?
				} else {
					ChunkXxHashMap::decode_directly(segment)?
				};
				let inner_map = map.flush();
				
				let borrowed_metadata = &mut self.metadata.lock().unwrap();
				match borrowed_metadata.preloaded_chunkmaps {
					PreloadedChunkMaps::None => initialize_new_map_if_empty(Arc::clone(&self.metadata)),
					PreloadedChunkMaps::InMemory(ref mut maps) => maps.xxhashs.extend(inner_map),
					PreloadedChunkMaps::Redb(ref mut db) => {
						for (chunk_no, value) in inner_map {
							preloaded_redb_chunk_xxhash_map_add_entry(db, chunk_no, value)?;
						}
					}
				}
			}				
		}

		Ok(())
	}

	/// Preloads all xxhash chunk maps for the specific object.
	pub fn preload_chunk_xxhash_map_per_object(&mut self, object_number: u64) -> Result<()> {
		initialize_new_map_if_empty(Arc::clone(&self.metadata));

		#[cfg(feature = "log")]
		log::debug!("Preloading chunk xxhash map for object {}", object_number);
		let obj_reader = match self.object_reader.get(&object_number) {
			Some(reader) => reader,
			None => return Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string())),
		};

		let chunk_numbers = get_chunks_of_unencrypted_object(&self.object_reader, object_number)?;
		let enc_info = get_enc_info_from_obj_reader(obj_reader)?;

		for chunk_no in chunk_numbers {
			self.preload_chunk_xxhash_map(chunk_no, &enc_info)?;
		}
		Ok(())
	}

	/// Preloads all xxhash chunks
	pub fn preload_chunk_xxhash_map_full(&mut self) -> Result<()> {
		let obj_numbers = self.unencrypted_object_no();
		for obj_no in obj_numbers {
			self.preload_chunk_xxhash_map_per_object(obj_no)?;
		}

		Ok(())
	}

	/// Preloads the chunk samebytes map of the given highest chunk number of the map.
	/// If no chunkmap was initialized, a new in-memory map will be initialized by using this method.
	fn preload_chunk_samebytes_map(&mut self, chunk_number: u64, encryption_information: &Option<EncryptionInformation>) -> Result<()> {
		let segments = &mut self.metadata.lock().unwrap().segments;
		for segment in segments.values_mut() {
			if let Some(offset) = segment.footer().chunk_samebytes_map_table.get(&chunk_number) {
				segment.seek(SeekFrom::Start(*offset))?;
				let mut map = if let Some(ref enc_info) = encryption_information {
					ChunkSamebytesMap::decrypt_and_decode(
						&enc_info.encryption_key, &enc_info.algorithm, segment, chunk_number)?
				} else {
					ChunkSamebytesMap::decode_directly(segment)?
				};
				let inner_map = map.flush();
				
				let borrowed_metadata = &mut self.metadata.lock().unwrap();
				match borrowed_metadata.preloaded_chunkmaps {
					PreloadedChunkMaps::None => initialize_new_map_if_empty(Arc::clone(&self.metadata)),
					PreloadedChunkMaps::InMemory(ref mut maps) => maps.same_bytes.extend(inner_map),
					PreloadedChunkMaps::Redb(ref mut db) => {
						for (chunk_no, value) in inner_map {
							preloaded_redb_chunk_samebytes_map_add_entry(db, chunk_no, value)?;
						}
					}
				}
			}				
		}

		Ok(())
	}

	/// Preloads all samebyte chunk maps for the specific object.
	pub fn preload_chunk_samebytes_map_per_object(&mut self, object_number: u64) -> Result<()> {
		initialize_new_map_if_empty(Arc::clone(&self.metadata));
		
		#[cfg(feature = "log")]
		log::debug!("Preloading chunk samebytes map for object {}", object_number);
		let obj_reader = match self.object_reader.get(&object_number) {
			Some(reader) => reader,
			None => return Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string())),
		};

		let chunk_numbers = get_chunks_of_unencrypted_object(&self.object_reader, object_number)?;
		let enc_info = get_enc_info_from_obj_reader(obj_reader)?;

		for chunk_no in chunk_numbers {
			self.preload_chunk_samebytes_map(chunk_no, &enc_info)?;
		}
		Ok(())
	}

	/// Preloads all samebyte chunks
	pub fn preload_chunk_samebytes_map_full(&mut self) -> Result<()> {
		let obj_numbers = self.unencrypted_object_no();
		for obj_no in obj_numbers {
			self.preload_chunk_samebytes_map_per_object(obj_no)?;
		}

		Ok(())
	}

	/// Preloads the chunk deduplication map of the given highest chunk number of the map.
	/// If no chunkmap was initialized, a new in-memory map will be initialized by using this method.
	fn preload_chunk_deduplication_map(&mut self, chunk_number: u64, encryption_information: &Option<EncryptionInformation>) -> Result<()> {
		let segments = &mut self.metadata.lock().unwrap().segments;
		for segment in segments.values_mut() {
			if let Some(offset) = segment.footer().chunk_dedup_map_table.get(&chunk_number) {
				segment.seek(SeekFrom::Start(*offset))?;
				let mut map = if let Some(ref enc_info) = encryption_information {
					ChunkDeduplicationMap::decrypt_and_decode(
						&enc_info.encryption_key, &enc_info.algorithm, segment, chunk_number)?
				} else {
					ChunkDeduplicationMap::decode_directly(segment)?
				};
				let inner_map = map.flush();
				
				let borrowed_metadata = &mut self.metadata.lock().unwrap();
				match borrowed_metadata.preloaded_chunkmaps {
					PreloadedChunkMaps::None => initialize_new_map_if_empty(Arc::clone(&self.metadata)),
					PreloadedChunkMaps::InMemory(ref mut maps) => maps.duplicate_chunks.extend(inner_map),
					PreloadedChunkMaps::Redb(ref mut db) => {
						for (chunk_no, value) in inner_map {
							preloaded_redb_chunk_deduplication_map_add_entry(db, chunk_no, value)?;
						}
					}
				}
			}				
		}

		Ok(())
	}

	/// Preloads all deduplication chunk maps for the specific object.
	pub fn preload_chunk_deduplication_map_per_object(&mut self, object_number: u64) -> Result<()> {
		initialize_new_map_if_empty(Arc::clone(&self.metadata));
		
		#[cfg(feature = "log")]
		log::debug!("Preloading chunk deduplication map for object {}", object_number);
		let obj_reader = match self.object_reader.get(&object_number) {
			Some(reader) => reader,
			None => return Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string())),
		};

		let chunk_numbers = get_chunks_of_unencrypted_object(&self.object_reader, object_number)?;
		let enc_info = get_enc_info_from_obj_reader(obj_reader)?;

		for chunk_no in chunk_numbers {
			self.preload_chunk_deduplication_map(chunk_no, &enc_info)?;
		}
		Ok(())
	}

	/// Preloads all deduplication chunks
	pub fn preload_chunk_deduplication_map_full(&mut self) -> Result<()> {
		let obj_numbers = self.unencrypted_object_no();
		for obj_no in obj_numbers {
			self.preload_chunk_deduplication_map_per_object(obj_no)?;
		}

		Ok(())
	}

	fn unencrypted_object_no(&self) -> Vec<u64> {
		let mut obj_numbers = Vec::new();
		for (obj_no, reader) in &self.object_reader {
			match reader {
				ZffObjectReader::Encrypted(_) => continue,
				_ => (),
			};
			obj_numbers.push(*obj_no);
		};
		obj_numbers
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

	/// Returns the [FileHeader] of the appropriate active file.
	/// # Error
	/// May fail if   
	/// - the active object is not a "logical" object.  
	/// - the active file number was not set.  
	/// - no object was set as active.  
	pub fn current_fileheader(&mut self) -> Result<FileHeader> {
		match self.object_reader.get(&self.active_object) {
			Some(ZffObjectReader::Logical(reader)) => reader.current_fileheader(),
			Some(ZffObjectReader::Physical(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_PHYSICAL_OBJECT)),
			Some(ZffObjectReader::Encrypted(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
			Some(ZffObjectReader::Virtual(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_VIRTUAL_OBJECT)),
			None => Err(ZffError::new(ZffErrorKind::MissingObjectNumber, self.active_object.to_string())),
		}
	}

	/// Returns the [FileFooter] of the appropriate active file.
	/// # Error
	/// May fail if   
	/// - the active object is not a "logical" object.  
	/// - the active file number was not set.  
	/// - no object was set as active.  
	pub fn current_filefooter(&mut self) -> Result<FileFooter> {
		match self.object_reader.get(&self.active_object) {
			Some(ZffObjectReader::Logical(reader)) => reader.current_filefooter(),
			Some(ZffObjectReader::Physical(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_PHYSICAL_OBJECT)),
			Some(ZffObjectReader::Encrypted(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
			Some(ZffObjectReader::Virtual(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, ERROR_ZFFREADER_OPERATION_VIRTUAL_OBJECT)),
			None => Err(ZffError::new(ZffErrorKind::MissingObjectNumber, self.active_object.to_string())),
		}
	}

	/// Returns a reference to the [ObjectHeader] of the appropriate active object.
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

	/// Returns the [ObjectFooter] of the appropriate active object.
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

	fn get_active_reader(&self) -> Result<&ZffObjectReader<R>> {
		match self.object_reader.get(&self.active_object) {
			Some(reader) => Ok(reader),
			None => Err(ZffError::new(ZffErrorKind::MissingObjectNumber, self.active_object.to_string())),
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
			object_reader.read(buffer)
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
			Err(ZffError::new(ZffErrorKind::MalformedSegment, "Could not decode segment footer"))
		}
	} else {
		reader.seek(SeekFrom::Start(position))?;
		Err(ZffError::new(ZffErrorKind::MalformedSegment, "Could not decode main footer"))
	}
}

fn get_chunk_data<R>(
	current_object_no: &u64,
	metadata: ArcZffReaderMetadata<R>,
	current_chunk_number: u64, 
	) -> std::result::Result<Vec<u8>, std::io::Error>
where
	R: Read + Seek
{
	let optional_chunk_offset = extract_offset_from_preloaded_chunkmap(
		&metadata.lock().unwrap().preloaded_chunkmaps, current_chunk_number);
	let optional_chunk_size = extract_size_from_preloaded_chunkmap(
		&metadata.lock().unwrap().preloaded_chunkmaps, current_chunk_number);
	let optional_chunk_flags = extract_flags_from_preloaded_chunkmap(
		&metadata.lock().unwrap().preloaded_chunkmaps, current_chunk_number);
	let optional_chunk_deduplication = extract_deduplication_chunks_from_preloaded_chunkmap(
		&metadata.lock().unwrap().preloaded_chunkmaps, current_chunk_number);
	//TODO: check if the xxhash should be compared in general (performance tests?)

	if let Some(dedup_chunk_no) = optional_chunk_deduplication {
		return get_chunk_data(current_object_no, metadata, dedup_chunk_no);
	};
	
	let segments = &mut metadata.lock().unwrap().segments;
	let segment = match get_segment_of_chunk_no(
	current_chunk_number, 
	&metadata.lock().unwrap().main_footer.chunk_offset_maps) 
	{
		Some(segment_no) => match segments.get_mut(&segment_no) {
			Some(segment) => segment,
			None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
		},
		None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
	};

	// unwrap should be safe here, while we already checked that this method only will be called from [ZffObjectReader]-methods.
	let borrowed_metadata = &metadata.lock().unwrap();
	let object_header_ref = borrowed_metadata.object_header_ref(&current_object_no).unwrap();
	let enc_information = EncryptionInformation::try_from(object_header_ref).ok();
	let compression_algorithm = &object_header_ref.compression_header.algorithm;

	let chunk_content = match segment.chunk_data(
		current_chunk_number, 
		&enc_information, 
		compression_algorithm, 
		optional_chunk_offset,
		optional_chunk_size,
		optional_chunk_flags.clone()) {
		Ok(data) => data,
		Err(e) => match e.unwrap_kind() {
			ZffErrorKind::IoError(io_error) => return Err(io_error),
			error => return Err(std::io::Error::new(std::io::ErrorKind::Other, error.to_string())) 
		},
	};
	match chunk_content {
		ChunkContent::Raw(data) => Ok(data),
		ChunkContent::SameBytes(single_byte) => {
			let original_chunk_size = object_header_ref.chunk_size;
			Ok(vec![single_byte; original_chunk_size as usize])
		},
		ChunkContent::Duplicate(dedup_chunk_no) => {
			get_chunk_data(current_object_no, Arc::clone(&metadata), dedup_chunk_no)	
		}
	}
}


fn initialize_object_reader_all<R: Read + Seek>(
	metadata: ArcZffReaderMetadata<R>) -> Result<HashMap<u64, ZffObjectReader<R>>> {

	let mut obj_reader_map = HashMap::new();
	for obj_no in metadata.lock().unwrap().main_footer.object_footer().keys() {
		let obj_reader = initialize_object_reader(
			*obj_no,
			Arc::clone(&metadata))?;
		obj_reader_map.insert(*obj_no, obj_reader);
	}
	Ok(obj_reader_map)
}

fn initialize_object_reader<R: Read + Seek>(
	object_number: u64, metadata: ArcZffReaderMetadata<R>) -> Result<ZffObjectReader<R>> {
	let borrowed_metadata = metadata.lock().unwrap();
	let segment_no_footer = match borrowed_metadata.main_footer.object_footer().get(&object_number) {
		None => return Err(ZffError::new(
			ZffErrorKind::MalformedSegment,
			format!("Could not find object footer of object no. {}", object_number))),
		Some(segment_no) => segment_no
	};
	let segment_no_header = match borrowed_metadata.main_footer.object_header().get(&object_number) {
		None => return Err(ZffError::new(
			ZffErrorKind::MalformedSegment, 
			format!("Could not find object header of object no. {}", object_number))),
		Some(segment_no) => segment_no
	};

	match metadata.lock().unwrap().segments.get_mut(segment_no_header) {
		None => Err(ZffError::new(ZffErrorKind::MissingSegment, segment_no_header.to_string())),
		Some(segment) => if segment.read_object_header(object_number).is_ok() {
							initialize_unencrypted_object_reader(
								object_number,
								*segment_no_header,
								*segment_no_footer,
								Arc::clone(&metadata))
						} else {
							initialize_encrypted_object_reader(
								object_number,
								*segment_no_header,
								*segment_no_footer,
								Arc::clone(&metadata))
						},
	}
}

fn initialize_unencrypted_object_reader<R: Read + Seek>(
	obj_number: u64,
	header_segment_no: u64,
	footer_segment_no: u64,
	metadata: ArcZffReaderMetadata<R>,
	) -> Result<ZffObjectReader<R>> {
	#[cfg(feature = "log")]
	debug!("Initialize unencrypted object reader for object {}", obj_number);
	let header = match metadata.lock().unwrap().segments.get_mut(&header_segment_no) {
		None => return Err(ZffError::new(ZffErrorKind::MissingSegment, header_segment_no.to_string())),
		Some(segment) => segment.read_object_header(obj_number)?,
	};
	
	let footer = match metadata.lock().unwrap().segments.get_mut(&footer_segment_no) {
		None => return Err(ZffError::new(ZffErrorKind::MissingSegment, header_segment_no.to_string())),
		Some(segment) => segment.read_object_footer(obj_number)?,
	};

	let obj_number = header.object_number;
	let obj_metadata = ObjectMetadata::new(header, footer.clone());
	metadata.lock().unwrap().object_metadata.insert(obj_number, obj_metadata);

	let obj_reader = match footer {
		ObjectFooter::Physical(_) => ZffObjectReader::Physical(Box::new(
			ZffObjectReaderPhysical::with_metadata(obj_number, Arc::clone(&metadata)))),
		ObjectFooter::Logical(_) => ZffObjectReader::Logical(Box::new(
			ZffObjectReaderLogical::with_obj_metadata_recommended(obj_number, Arc::clone(&metadata))?)),
		ObjectFooter::Virtual(_) => ZffObjectReader::Virtual(Box::new(
			ZffObjectReaderVirtual::with_data(obj_number, Arc::clone(&metadata)))),
	};
	Ok(obj_reader)
}

fn initialize_encrypted_object_reader<R: Read + Seek>(
	obj_number: u64,
	header_segment_no: u64,
	footer_segment_no: u64,
	metadata: ArcZffReaderMetadata<R>,
	) -> Result<ZffObjectReader<R>> {

	let header = match metadata.lock().unwrap().segments.get_mut(&header_segment_no) {
		None => return Err(ZffError::new(ZffErrorKind::MissingSegment, header_segment_no.to_string())),
		Some(segment) => segment.read_encrypted_object_header(obj_number)?,
	};
	let footer = match metadata.lock().unwrap().segments.get_mut(&footer_segment_no) {
		None => return Err(ZffError::new(ZffErrorKind::MissingSegment, header_segment_no.to_string())),
		Some(segment) => segment.read_encrypted_object_footer(obj_number)?,
	};
	let obj_reader = ZffObjectReader::Encrypted(
		Box::new(ZffObjectReaderEncrypted::with_data(header, footer, Arc::clone(&metadata))));
	Ok(obj_reader)
}

fn preloaded_redb_chunk_offset_map_add_entry(db: &mut Database, chunk_no: u64, offset: u64) -> Result<()> {
	let write_txn = db.begin_write()?;
	{
		let mut table = write_txn.open_table(PRELOADED_CHUNK_OFFSET_MAP_TABLE)?;
		table.insert(chunk_no, offset)?;
	}
	write_txn.commit()?;
	Ok(())
}

fn preloaded_redb_chunk_size_map_add_entry(db: &mut Database, chunk_no: u64, size: u64) -> Result<()> {
	let write_txn = db.begin_write()?;
	{
		let mut table = write_txn.open_table(PRELOADED_CHUNK_SIZE_MAP_TABLE)?;
		table.insert(chunk_no, size)?;
	}
	write_txn.commit()?;
	Ok(())
}

fn preloaded_redb_chunk_flags_map_add_entry(db: &mut Database, chunk_no: u64, flags: ChunkFlags) -> Result<()> {
	let write_txn = db.begin_write()?;
	{
		let mut table = write_txn.open_table(PRELOADED_CHUNK_FLAGS_MAP_TABLE)?;
		table.insert(chunk_no, flags.as_bytes())?;
	}
	write_txn.commit()?;
	Ok(())
}

fn preloaded_redb_chunk_xxhash_map_add_entry(db: &mut Database, chunk_no: u64, xxhash: u64) -> Result<()> {
	let write_txn = db.begin_write()?;
	{
		let mut table = write_txn.open_table(PRELOADED_CHUNK_XXHASH_MAP_TABLE)?;
		table.insert(chunk_no, xxhash)?;
	}
	write_txn.commit()?;
	Ok(())
}

fn preloaded_redb_chunk_samebytes_map_add_entry(db: &mut Database, chunk_no: u64, same_byte: u8) -> Result<()> {
	let write_txn = db.begin_write()?;
	{
		let mut table = write_txn.open_table(PRELOADED_CHUNK_SAME_BYTES_MAP_TABLE)?;
		table.insert(chunk_no, same_byte)?;
	}
	write_txn.commit()?;
	Ok(())
}

fn preloaded_redb_chunk_deduplication_map_add_entry(db: &mut Database, chunk_no: u64, duplicated: u64) -> Result<()> {
	let write_txn = db.begin_write()?;
	{
		let mut table = write_txn.open_table(PRELOADED_CHUNK_DUPLICATION_MAP_TABLE)?;
		table.insert(chunk_no, duplicated)?;
	}
	write_txn.commit()?;
	Ok(())
}

// tries to extract the appropriate offset of the given chunk number.
// returns a None in case of error or if the chunkmap is a [PreloadedChunkmap::None].
fn extract_offset_from_preloaded_chunkmap(preloaded_chunkmap: &PreloadedChunkMaps, chunk_number: u64) -> Option<u64> {
	match preloaded_chunkmap {
		PreloadedChunkMaps::None => None,
		PreloadedChunkMaps::InMemory(preloaded_maps) => {
			preloaded_maps.offsets.get(&chunk_number).copied()
		},
		PreloadedChunkMaps::Redb(db) => {
			let read_txn = db.begin_read().ok()?;
    		let table = read_txn.open_table(PRELOADED_CHUNK_OFFSET_MAP_TABLE).ok()?;
    		let value = table.get(&chunk_number).ok()??.value();
    		Some(value)
		}
	}
}

// tries to extract the appropriate size (size of the compressed chunk) of the given chunk number.
// returns a None in case of error or if the chunkmap is a [PreloadedChunkmaps::None].
fn extract_size_from_preloaded_chunkmap(preloaded_chunkmap: &PreloadedChunkMaps, chunk_number: u64) -> Option<u64> {
	match preloaded_chunkmap {
		PreloadedChunkMaps::None => None,
		PreloadedChunkMaps::InMemory(preloaded_maps) => {
			preloaded_maps.sizes.get(&chunk_number).copied()
		},
		PreloadedChunkMaps::Redb(db) => {
			let read_txn = db.begin_read().ok()?;
    		let table = read_txn.open_table(PRELOADED_CHUNK_SIZE_MAP_TABLE).ok()?;
    		let value = table.get(&chunk_number).ok()??.value();
    		Some(value)
		}
	}
}

// tries to extract the appropriate flags of the given chunk number.
// returns a None in case of error or if the chunkmap is a [PreloadedChunkmaps::None].
fn extract_flags_from_preloaded_chunkmap(preloaded_chunkmap: &PreloadedChunkMaps, chunk_number: u64) -> Option<ChunkFlags> {
	match preloaded_chunkmap {
		PreloadedChunkMaps::None => None,
		PreloadedChunkMaps::InMemory(preloaded_maps) => {
			preloaded_maps.flags.get(&chunk_number).cloned()
		},
		PreloadedChunkMaps::Redb(db) => {
			let read_txn = db.begin_read().ok()?;
    		let table = read_txn.open_table(PRELOADED_CHUNK_FLAGS_MAP_TABLE).ok()?;
    		let value = table.get(&chunk_number).ok()??.value();
    		Some(value.into())
		}
	}
}

fn extract_deduplication_chunks_from_preloaded_chunkmap(preloaded_chunkmap: &PreloadedChunkMaps, chunk_number: u64) -> Option<u64> {
	match preloaded_chunkmap {
		PreloadedChunkMaps::None => None,
		PreloadedChunkMaps::InMemory(preloaded_maps) => {
			preloaded_maps.duplicate_chunks.get(&chunk_number).cloned()
		},
		PreloadedChunkMaps::Redb(db) => {
  			let read_txn = db.begin_read().ok()?;
    		let table = read_txn.open_table(PRELOADED_CHUNK_DUPLICATION_MAP_TABLE).ok()?;
    		let value = table.get(&chunk_number).ok()??.value();
			Some(value.into())
		}
	}
}

// tries to extract the appropriate sambyte of the given chunk number.
// returns a None in case of error or if the chunkmap is a [PreloadedChunmaps::None].
fn extract_samebyte_from_preloaded_chunkmap(preloaded_chunkmap: &PreloadedChunkMaps, chunk_number: u64) -> Option<u8> {
	match preloaded_chunkmap {
		PreloadedChunkMaps::None => None,
		PreloadedChunkMaps::InMemory(preloaded_maps) => {
			preloaded_maps.same_bytes.get(&chunk_number).cloned()
		},
		PreloadedChunkMaps::Redb(db) => {
			let read_txn = db.begin_read().ok()?;
    		let table = read_txn.open_table(PRELOADED_CHUNK_SAME_BYTES_MAP_TABLE).ok()?;
    		let value = table.get(&chunk_number).ok()??.value();
    		Some(value.into())
		}
	}
}

fn get_chunks_of_unencrypted_object<R: Read + Seek>(
	object_reader: &HashMap<u64, ZffObjectReader<R>>, 
	object_number: u64) -> Result<Vec<u64>> {
	let obj_reader = match object_reader.get(&object_number) {
		Some(reader) => reader,
		None => return Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string())),
	};
	
	let chunk_numbers = match obj_reader {
		ZffObjectReader::Physical(reader) => {
			let first_chunk = reader.object_footer_unwrapped_ref().first_chunk_number;
			let last_chunk = reader.object_footer_unwrapped_ref().number_of_chunks + first_chunk - 1;
			(first_chunk..=last_chunk).collect::<Vec<_>>()
		},
		ZffObjectReader::Logical(reader) => {
			let mut chunk_numbers = Vec::new();
			for filemetadata in reader.files().values() {
				let first_chunk_no = filemetadata.first_chunk_number;
				let last_chunk_no = filemetadata.number_of_chunks + first_chunk_no - 1;
				chunk_numbers.extend(first_chunk_no..=last_chunk_no);
			}
			chunk_numbers
		},
		ZffObjectReader::Virtual(reader) => {
			let passive_objects = reader.object_footer_unwrapped_ref().passive_objects.clone();
			let mut chunk_numbers = Vec::new();
			for obj_no in passive_objects {
				chunk_numbers.extend(get_chunks_of_unencrypted_object(object_reader, obj_no)?);
			}
			chunk_numbers.sort();
			chunk_numbers.dedup();
			chunk_numbers
		},
		ZffObjectReader::Encrypted(_) => {
			return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, ""));
		},
	};

	Ok(chunk_numbers)
}

fn get_enc_info_from_obj_reader<R: Read + Seek>(object_reader: &ZffObjectReader<R>) -> Result<Option<EncryptionInformation>> {
		let enc_info = match object_reader {
		ZffObjectReader::Physical(reader) => EncryptionInformation::try_from(reader.object_header_ref()),
		ZffObjectReader::Virtual(reader) => EncryptionInformation::try_from(reader.object_header_ref()),
		ZffObjectReader::Logical(reader) => EncryptionInformation::try_from(reader.object_header_ref()),
		ZffObjectReader::Encrypted(_) => return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, "")),
	};
	let enc_info = match enc_info {
		Ok(enc_info) => Some(enc_info),
		Err(e) => match e.get_kind() {
			ZffErrorKind::MissingEncryptionHeader => None,
			_ => return Err(e),
		},
	};
	Ok(enc_info)
}

fn initialize_new_map_if_empty<R: Read + Seek>(metadata: ArcZffReaderMetadata<R>) {
	let preloaded_chunkmaps = &metadata.lock().unwrap().preloaded_chunkmaps;
	let new_preloaded_chunkmaps = match preloaded_chunkmaps {
		PreloadedChunkMaps::None => {
			PreloadedChunkMaps::InMemory(PreloadedChunkMapsInMemory {
				..Default::default()
			})
		},
		_ => return,
	};
	metadata.lock().unwrap().preloaded_chunkmaps = new_preloaded_chunkmaps;
}