// - STD
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::{Error as IoError, ErrorKind as IoErrorKind, Read, Seek, SeekFrom};
use std::sync::{Arc, OnceLock, RwLock};

// - internal
use crate::prelude::*;
use crate::{
	FileMetadata,
	header::ObjectType as HeaderObjectType,
	helper::get_segment_of_chunk_no,
	Segment,
};

// - modules
mod zffobjectreader;
mod redb_handling;

// - re-exports
pub(crate) use zffobjectreader::*;
pub(crate) use redb_handling::*;

// - type definitions
// This is a Arc instead of a Rc to optain more flexibility by using the [ZffReader] 
// (Rc / RefCell do not implement Send :-( )).
type ArcZffReaderMetadata<R> = Arc<ZffReaderGeneralMetadata<R>>;
type ArcSegment<R> = Arc<HashMap<u64, Segment<R>>>;

// - external
use redb::{Database, ReadableTable, ReadableDatabase};
#[cfg(feature = "log")]
use log::{debug, trace};

/// Defines the recognized object type (used by the [ZffReader]). 
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ObjectType {
	/// Physical object
	Physical,
	/// Logical object
	Logical,
	/// Virtual object,
	Virtual,
	/// Encrypted object
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
	chunk_header: HashMap<u64, ChunkHeader>,
	same_bytes: HashMap<u64, u8>,
	duplicate_chunks: HashMap<u64, u64>,
}

impl PreloadedChunkMapsInMemory {
	pub fn new(
		chunk_header: HashMap<u64, ChunkHeader>, 
		same_bytes: HashMap<u64, u8>, 
		duplicate_chunks: HashMap<u64, u64>
	) -> Self {
		Self {
			chunk_header,
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
			PreloadedChunkMaps::None => (),
			PreloadedChunkMaps::InMemory(map) => convert_in_memory_preloaded_chunkmaps_into_redb(&mut db, map)?,
			PreloadedChunkMaps::Redb(old_db) => copy_redb(old_db, &mut db)?,
		};
		*self = PreloadedChunkMaps::Redb(db);
		Ok(())
	}

	fn get_samebyte(&self, chunk_no: u64) -> Option<u8> {
		extract_samebyte_from_preloaded_chunkmap(self, chunk_no)
	}
}

/// internally handled metadata for the [ZffReader] (and appropriate [ZffObjectReader])
#[derive(Debug)]
pub(crate) struct ZffReaderGeneralMetadata<R: ReadAt> {
	pub segments: ArcSegment<R>, //<segment number, Segment>
	pub object_metadata: Arc<BTreeMap<u64, OnceLock<ObjectMetadata>>>, //<object number, ObjectMetadata>
	pub main_footer: MainFooter,
	pub preloaded_chunkmaps: Arc<RwLock<PreloadedChunkMaps>>,
}

impl<R: ReadAt> ZffReaderGeneralMetadata<R> {
	fn new(segments: HashMap<u64, Segment<R>>, main_footer: MainFooter) -> Self {
		let object_metadata = main_footer
		.object_header
		.keys()
		.map(|object_no| (*object_no, OnceLock::new()))
		.collect();

		Self {
			segments: Arc::new(segments),
			object_metadata: Arc::new(object_metadata),
			main_footer,
			preloaded_chunkmaps: Arc::new(RwLock::new(PreloadedChunkMaps::default())),
		}
	}

	/// Returns a Clone of the appropriate [ObjectHeader](crate::header::ObjectHeader) to the given Object number.
	pub fn object_header(&self, object_no: &u64) -> Option<ObjectHeader> {
		Some(self.object_metadata.get(object_no)?.get()?.header.clone())
	}

	/// Returns a Clone of the appropriate [ObjectFooter](crate::header::ObjectFooter) to the given Object number.
	pub fn object_footer(&self, object_no: &u64) -> Option<ObjectFooter> {
		Some(self.object_metadata.get(object_no)?.get()?.footer.clone())
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
pub struct ZffReader<R: ReadAt> {
	metadata: ArcZffReaderMetadata<R>,
	object_reader: HashMap<u64, ZffObjectReader<R>>, //<object_number, ZffObjectReader>,
	active_object: u64, //the number of the active object.
}

impl<R: ReadAt> ZffReader<R> {
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
			// Segment Header should always be found at offset 0. ;)
			let segment_header = SegmentHeader::decode_at(&reader, 0)?;
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
			None => return Err(ZffError::new(ZffErrorKind::Missing, ERROR_MISSING_SEGMENT_MAIN_FOOTER)),
		};

		let metadata = Arc::new(ZffReaderGeneralMetadata::new(segments, main_footer));
		#[cfg(feature = "log")]
		debug!("Successfully initialized ZffReader.");
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
	pub fn list_objects(&self) -> Result<BTreeMap<u64, ObjectType>> {
		#[cfg(feature = "log")]
		trace!("list objects of ZffReader.");
		
		let mut map = BTreeMap::new();
		for (object_number, segment_number) in &self.metadata.main_footer.object_header {
			let segment = match self.metadata.segments.get(segment_number) {
				Some(segment) => segment,
				None => return Err(ZffError::new(ZffErrorKind::Missing, segment_number.to_string())),
			};
			if let Ok(obj_header) = segment.read_object_header(*object_number) {
				let obj_type = match obj_header.object_type {
					HeaderObjectType::Physical => ObjectType::Physical,
					HeaderObjectType::Logical => ObjectType::Logical,
					HeaderObjectType::Virtual => ObjectType::Virtual,
				};
				#[cfg(feature = "log")]
				trace!("list_objects(): {obj_type} added to list.");
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
			Err(ZffError::new(
				ZffErrorKind::Missing,
				format!("{ERROR_MISSING_OBJECT_NO}{object_number}")))
		}
	}

	/// Pre-initializes all filemaps of the active virtual object.
	/// This can speed up later file access, but increases memory usage.
	///
	/// If the active object is not a virtual object, this method does nothing.
	/// # Error
	/// Fails if the filemaps of the active virtual object cannot be initialized.
	pub fn preinitialize_virtual_object_filemaps(&mut self) -> Result<()> {
		if let Some(ZffObjectReader::Virtual(obj_reader)) = self.object_reader.get_mut(&self.active_object) {
			obj_reader.initialize_filemaps()?
		}
		Ok(())
	}

	///  Sets an appropriate file as active to read or seek from this object.
	///  # Error
	///  This method fails, if the appropriate object type is not "logical" or "virtual logical",
	///  or if no file for the appropriate file number exists.
	///  Will also fail, if no object was activated by using the set_active_object() method.
	pub fn set_active_file(&mut self, filenumber: u64) -> Result<()> {
		if let Some(object_reader) = self.object_reader.get_mut(&self.active_object) {
			match object_reader {
				ZffObjectReader::Logical(reader) => reader.set_active_file(filenumber),
				ZffObjectReader::Virtual(reader) => reader.set_active_file(filenumber),
				_ => Err(ZffError::new(
					ZffErrorKind::Invalid,
					 self.active_object.to_string()))
			}
		} else {
			Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("{ERROR_MISSING_OBJECT_NO}{}", self.active_object)))
		}
	}

	/// Returns the [FileHeader] of the appropriate active file.
	/// # Error
	/// May fail if   
	/// - the active object is not a "logical" object.  
	/// - the active file number was not set.  
	/// - no object was set as active.  
	pub fn current_fileheader(&self) -> Result<FileHeader> {
		match self.object_reader.get(&self.active_object) {
			Some(ZffObjectReader::Logical(reader)) => reader.current_fileheader(),
			Some(ZffObjectReader::Physical(_)) => Err(ZffError::new(ZffErrorKind::Invalid, ERROR_ZFFREADER_OPERATION_PHYSICAL_OBJECT)),
			Some(ZffObjectReader::Encrypted(_)) => Err(ZffError::new(ZffErrorKind::Invalid, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
			Some(ZffObjectReader::Virtual(reader)) => reader.current_fileheader(),
			None => Err(ZffError::new(ZffErrorKind::Missing, self.active_object.to_string())),
		}
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
				Ok(reader.current_filemetadata()?)
			},
			Some(ZffObjectReader::Physical(_)) => Err(ZffError::new(ZffErrorKind::Invalid, ERROR_ZFFREADER_OPERATION_PHYSICAL_OBJECT)),
			Some(ZffObjectReader::Encrypted(_)) => Err(ZffError::new(ZffErrorKind::Invalid, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
			Some(ZffObjectReader::Virtual(reader)) => reader.current_filemetadata(),
			None => Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("{ERROR_MISSING_OBJECT_NO}{}", self.active_object))),
		}
	}

	/// Returns the [FileMetadata] for the given file(number) from given object(number).
	pub fn filemetadata(&self, object_number: u64, file_number: u64) -> Result<&FileMetadata> {
		match self.object_reader.get(&object_number) {
			Some(ZffObjectReader::Logical(reader)) => {
				Ok(reader.filemetadata_by_filenumber(file_number)?)
			},
			Some(ZffObjectReader::Physical(_)) => Err(ZffError::new(ZffErrorKind::Invalid, ERROR_ZFFREADER_OPERATION_PHYSICAL_OBJECT)),
			Some(ZffObjectReader::Encrypted(_)) => Err(ZffError::new(ZffErrorKind::Invalid, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
			Some(ZffObjectReader::Virtual(reader)) => reader.filemetadata_by_filenumber(file_number),
			None => Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("{ERROR_MISSING_OBJECT_NO}{}", self.active_object))),
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
		let (chunk_number, _) = self.metadata.main_footer.chunk_header_maps.last_key_value().unwrap_or((&0, &0));
		*chunk_number
	}

	/// Returns a list of all xxhashes (of all unencrypted objects) 
	/// as BTreeMap<u64, u64> (chunk_no / appropriate xxhash)
	pub fn get_xxhashmaps_unencrypted(&self) -> Result<BTreeMap<u64, u64>> {
		let mut map = BTreeMap::new();
		for segment in self.metadata.segments.values() {
			let map_table = segment.footer().chunk_header_map_table.clone();
			//trying to decode the map entries - will fail if the map is encrypted.
			for offset in map_table.values() {
				match ChunkHeaderMap::decode_at( segment, *offset) {
					Ok(inner_map) => inner_map
														.chunkmap()
														.iter()
														.for_each(|(chunk_no, header) | {
															map.insert(*chunk_no, header.integrity_hash);
														}),
					Err(e) => return Err(e),
				}
			}
		}
		Ok(map)
	}

	/// Returns the Data of the given chunk no
	/// # Error
	/// - If the object is encrypted, it will return an error.
	/// - If the chunk number is out of range, it will return an error.
	pub fn chunk_data(&self, chunk_no: u64) -> Result<Vec<u8>> {
		let segment = match get_segment_of_chunk_no(
			chunk_no, 
			&self.metadata.main_footer.chunk_header_maps) 
		{
			Some(segment_no) => match self.metadata.segments.get(&segment_no) {
				Some(segment) => segment,
				None => return Err(ZffError::new(ZffErrorKind::NotFound, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
			},
			None => return Err(ZffError::new(ZffErrorKind::NotFound, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
		};
		// search for the appropriate object number
		let preloaded_chunkmaps = self.metadata.preloaded_chunkmaps.read()?;
		let chunk_header = match extract_chunk_header_from_preloaded_chunkmap(&preloaded_chunkmaps, chunk_no) {
			Some(header) => header,
			None => segment.get_chunk_header(&chunk_no)?, 
		};

		if chunk_header.flags.encryption {
			return Err(ZffError::new(ZffErrorKind::Invalid, format!("{ERROR_CHUNK_IS_ENCRYPTED_}{chunk_no}")));
		}

		let object_number = segment.get_object_number(chunk_no)?;
		let object_header = match self.metadata.object_metadata.get(&object_number) {
			Some(obj_metadata) => {
				&obj_metadata
				.get()
				.ok_or(ZffError::new(ZffErrorKind::Missing, format!("{ERROR_MISSING_OBJECT_NO}{object_number}")))?
				.header
			},
			None => return Err(ZffError::new(ZffErrorKind::Missing, format!("{ERROR_MISSING_OBJECT_NO}{object_number}"))),
		};

		match segment.chunk_data(
			chunk_no, 
			&None::<EncryptionInformation>, 
			&object_header.compression_header.algorithm, 
			Some(chunk_header.offset), 
			Some(chunk_header.size), 
			Some(chunk_header.flags))? {
				ChunkContent::Raw(data) => Ok(data),
				ChunkContent::Duplicate(chunk_no) => self.chunk_data(chunk_no),
				ChunkContent::SameBytes(single_byte) => Ok(vec![single_byte; object_header.chunk_size as usize])
			}
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
			None => return Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("{ERROR_MISSING_OBJECT_NO}{object_number}"))),
		};
		let decrypted_reader = match object_reader {
			ZffObjectReader::Encrypted(reader) => reader.decrypt_with_password(decryption_password)?,
			_ => return Err(ZffError::new(
				ZffErrorKind::EncryptionError,
				NO_ENCRYPTION_DETECTED))
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
		self.metadata.preloaded_chunkmaps.write().unwrap().set_mode_in_memory()?;
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
		self.metadata.preloaded_chunkmaps.write().unwrap().set_mode_redb(db)
	}

	/// Automatically preloads all maps of the specific object (will be used in case of encrypted maps for performance reasons).
	fn auto_preload_object_maps(&mut self, object_number: u64) -> Result<()> {
		self.preload_chunk_header_map_per_object(object_number)?;
		self.preload_chunk_samebytes_map_per_object(object_number)?;
		self.preload_chunk_deduplication_map_per_object(object_number)?;
		Ok(())
	}

	/// Preloads the chunk header map of the given highest chunk number of the map.
	/// If no chunkmap was initialized, a new in-memory map will be initialized by using this method.
	fn preload_chunk_header_map(&mut self, chunk_number: u64, encryption_information: &Option<EncryptionInformation>) -> Result<()> {
		if let Some((segment_no, offset)) = chunkmap_offset_info(ChunkMapType::HeaderMap, chunk_number, &self.metadata) {
			if let Some(segment) = self.metadata.segments.get(&segment_no) {
				let mut map = if let Some(ref enc_info) = encryption_information {
					ChunkHeaderMap::decrypt_and_decode_at(
						&enc_info.encryption_key, &enc_info.algorithm, segment, chunk_number, offset)?
				} else {
					ChunkHeaderMap::decode_at(segment, offset)?
				};
				let inner_map = map.flush();
				
				let mut preloaded_chunkmaps = self.metadata.preloaded_chunkmaps.write().unwrap();
				match *preloaded_chunkmaps {
					PreloadedChunkMaps::None => initialize_new_map_if_empty(Arc::clone(&self.metadata)),
					PreloadedChunkMaps::InMemory(ref mut maps) => maps.chunk_header.extend(inner_map),
					PreloadedChunkMaps::Redb(ref mut db) => {
						for (chunk_no, value) in inner_map {
							preloaded_redb_chunk_header_map_add_entry(db, chunk_no, value)?;
						}
					}
				}
			}
		}				
		Ok(())
	}

	/// Preloads all chunk header maps for the specific object.
	pub fn preload_chunk_header_map_per_object(&mut self, object_number: u64) -> Result<()> {
		initialize_new_map_if_empty(Arc::clone(&self.metadata));
		
		#[cfg(feature = "log")]
		log::debug!("Preloading chunk offset map for object {}", object_number);
		let obj_reader = match self.object_reader.get(&object_number) {
			Some(reader) => reader,
			None => return Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("{ERROR_MISSING_OBJECT_NO}{object_number}"))),
		};
		let chunk_numbers = get_chunks_of_unencrypted_object(&self.object_reader, object_number)?;
		let enc_info = get_enc_info_from_obj_reader(obj_reader)?;
		for chunk_no in chunk_numbers {
			self.preload_chunk_header_map(chunk_no, &enc_info)?;
		}
		Ok(())
	}

	/// Preloads all chunk header maps for all objects.
	pub fn preload_chunk_header_map_full(&mut self) -> Result<()> {
		let obj_numbers = self.unencrypted_object_no();
		for obj_no in obj_numbers {
			self.preload_chunk_header_map_per_object(obj_no)?;
		}

		Ok(())
	}

	/// Preloads the chunk samebytes map of the given highest chunk number of the map.
	/// If no chunkmap was initialized, a new in-memory map will be initialized by using this method.
	fn preload_chunk_samebytes_map(&mut self, chunk_number: u64, encryption_information: &Option<EncryptionInformation>) -> Result<()> {
		for segment in  self.metadata.segments.values() {
			if let Some(offset) = segment.footer().chunk_samebytes_map_table.get(&chunk_number) {
				let mut map = if let Some(ref enc_info) = encryption_information {
					ChunkSamebytesMap::decrypt_and_decode_at(
						&enc_info.encryption_key, &enc_info.algorithm, segment, chunk_number, *offset)?
				} else {
					ChunkSamebytesMap::decode_at(segment, *offset)?
				};
				let inner_map = map.flush();
				
				let mut preloaded_chunkmaps = self.metadata.preloaded_chunkmaps.write().unwrap();
				match *preloaded_chunkmaps {
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
			None => return Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("{ERROR_MISSING_OBJECT_NO}{object_number}"))),
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
		for segment in self.metadata.segments.values() {
			if let Some(offset) = segment.footer().chunk_dedup_map_table.get(&chunk_number) {
				let mut map = if let Some(ref enc_info) = encryption_information {
					ChunkDeduplicationMap::decrypt_and_decode_at(
						&enc_info.encryption_key, &enc_info.algorithm, segment, chunk_number, *offset)?
				} else {
					ChunkDeduplicationMap::decode_at(segment, *offset)?
				};
				let inner_map = map.flush();
				
				let mut preloaded_chunkmaps = self.metadata.preloaded_chunkmaps.write().unwrap();
				match *preloaded_chunkmaps {
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
			None => return Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("{ERROR_MISSING_OBJECT_NO}{object_number}"))),
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
			if let ZffObjectReader::Encrypted(_) = reader { continue };
			obj_numbers.push(*obj_no);
		};
		obj_numbers
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
			ZffObjectReader::Encrypted(_) => Err(ZffError::new(ZffErrorKind::Invalid, ""))
		}
	}

	/// Returns the [ObjectFooter] of the appropriate active object.
	/// # Error
	/// May fail if   
	/// - the object does not exist.
	/// - the object was not decrypted.
	pub fn object_footer(&self, object_number: u64) -> Result<ObjectFooter> {
		self.object_reader
		.get(&object_number)
		.ok_or(ZffError::new(ZffErrorKind::Missing, format!("{ERROR_ZFFREADER_MISSING_OBJECT}{}", object_number)))?
		.footer()
	}

	fn get_active_reader(&self) -> Result<&ZffObjectReader<R>> {
		match self.object_reader.get(&self.active_object) {
			Some(reader) => Ok(reader),
			None => Err(ZffError::new(
				ZffErrorKind::Missing, 
				format!("{ERROR_ZFFREADER_MISSING_OBJECT}{}", self.active_object))),
		}
	}

	/// Reads the approrpriate bytes into the buffer (for given objectnumber/filenumber) at given offset.
	pub fn read_at(&self, buf: &mut [u8], object_number: u64, file_number: u64, offset: u64) -> std::io::Result<usize> {
		let reader = match self.object_reader.get(&object_number) {
			Some(reader) => reader,
			None => return Err(IoError::new(IoErrorKind::NotFound, format!("{ERROR_MISSING_OBJECT_NO}{object_number}"))),
		};
		reader.read_at_file(buf, offset, file_number)
	}

	/// Same as read_to_end, but starts at the appropriate offset.
	pub fn read_at_to_end(&self, buf: &mut Vec<u8>, object_number: u64, file_no: u64, offset: u64) -> std::io::Result<usize> {
		let reader = match self.object_reader.get(&object_number) {
			Some(reader) => reader,
			None => return Err(IoError::new(IoErrorKind::NotFound, format!("{ERROR_MISSING_OBJECT_NO}{object_number}"))),
		};
		reader.read_at_file_to_end(buf, offset, file_no)
	}
}

impl<R: ReadAt> Read for ZffReader<R> {
	fn read(&mut self, buffer: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
		let object_reader = match self.object_reader.get_mut(&self.active_object) {
			Some(object_reader) => object_reader,
			None => return Err(std::io::Error::other(format!("{ERROR_ZFFREADER_MISSING_OBJECT}{}", self.active_object)))
		};
		object_reader.read(buffer)
	}
}

impl<R: ReadAt> Seek for ZffReader<R> {
	fn seek(&mut self, seek_from: SeekFrom) -> std::result::Result<u64, std::io::Error> {
		let object_reader = match self.object_reader.get_mut(&self.active_object) {
			Some(object_reader) => object_reader,
			None => return Err(std::io::Error::other(format!("{ERROR_ZFFREADER_MISSING_OBJECT}{}", self.active_object)))
		};
		object_reader.seek(seek_from)
	}
}

enum Footer {
	Segment(SegmentFooter),
	MainAndSegment((MainFooter, SegmentFooter))
}


fn try_find_footer<R: ReadAt>(reader: &mut R) -> Result<Footer> {
	let reader_size = reader.size()?;
	let mut footer_offset = u64::decode_at(reader, reader_size-8)?; //uses the end to reads the last 8 bytes (footer offset)

	if let Ok(segment_footer) = SegmentFooter::decode_at(reader, footer_offset) {
		return Ok(Footer::Segment(segment_footer));
	}
	if let Ok(main_footer) = MainFooter::decode_at(reader, footer_offset) {
		footer_offset = u64::decode_at(reader, footer_offset-8)?;
		if let Ok(segment_footer) = SegmentFooter::decode_at(reader, footer_offset) {
			Ok(Footer::MainAndSegment((main_footer, segment_footer)))
		} else {
			Err(ZffError::new(ZffErrorKind::EncodingError, ERROR_UNDECODABLE_SEGMENT_FOOTER))
		}
	} else {
		Err(ZffError::new(ZffErrorKind::EncodingError, ERROR_UNDECODABLE_MAIN_FOOTER))
	}
}

fn get_chunk_data<R>(
	current_object_no: &u64,
	metadata: ArcZffReaderMetadata<R>,
	current_chunk_number: u64, 
	) -> std::result::Result<ChunkContent, std::io::Error>
where
	R: ReadAt
{
	let optional_chunk_header = extract_chunk_header_from_preloaded_chunkmap(
		&metadata.preloaded_chunkmaps.read().unwrap(), current_chunk_number);
	let optional_chunk_deduplication = extract_deduplication_chunks_from_preloaded_chunkmap(
		&metadata.preloaded_chunkmaps.read().unwrap(), current_chunk_number);

	if let Some(dedup_chunk_no) = optional_chunk_deduplication {
		return get_chunk_data(current_object_no, metadata, dedup_chunk_no);
	};
	
	//let original_chunk_size;
	let chunk_content = {
		// Implicitly drops the RAII when exiting the Scope (necessary if the ChunkContent 
		// is a Duplicate - while we try to recursivly use the get_chunk_data()-method).
		let segment = match get_segment_of_chunk_no(
		current_chunk_number, 
		&metadata.main_footer.chunk_header_maps) 
		{
			Some(segment_no) => match metadata.segments.get(&segment_no) {
				Some(segment) => segment,
				None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
			},
			None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
		};
	
		// unwrap should be safe here, while we already checked that this method only will be called from [ZffObjectReader]-methods.
		//let object_header_ref = metadata.object_header_ref(&current_object_no).unwrap();
		let object_header_ref = &metadata.object_metadata
		.get(current_object_no)
		.ok_or(ZffError::new(ZffErrorKind::Missing, format!("{ERROR_MISSING_OBJECT_NO}{current_object_no}")))?
		.get()
		.ok_or(ZffError::new(ZffErrorKind::Missing, format!("{ERROR_MISSING_OBJECT_NO}{current_object_no}")))?
		.header;
		let enc_information = EncryptionInformation::try_from(object_header_ref).ok();
		let compression_algorithm = &object_header_ref.compression_header.algorithm;
		//original_chunk_size = object_header_ref.chunk_size;

		match segment.chunk_data(
			current_chunk_number, 
			&enc_information, 
			compression_algorithm, 
			optional_chunk_header.as_ref().map(|ch| ch.offset),
			optional_chunk_header.as_ref().map(|ch| ch.size),
			optional_chunk_header.as_ref().map(|ch| ch.flags)) {
			Ok(data) => data,
			Err(e) => {
				let error = e.kind();
				return Err(std::io::Error::other(error.to_string()))
			},
		}
	};

	match chunk_content {
		ChunkContent::Raw(_) | ChunkContent::SameBytes(_) => Ok(chunk_content),
		//ChunkContent::SameBytes(_) =>
		//{
			
			//Ok(vec![single_byte; original_chunk_size as usize])
		//},
		ChunkContent::Duplicate(dedup_chunk_no) => {
			get_chunk_data(current_object_no, Arc::clone(&metadata), dedup_chunk_no)	
		}
	}
}

fn initialize_object_reader_all<R: ReadAt>(
	metadata: ArcZffReaderMetadata<R>) -> Result<HashMap<u64, ZffObjectReader<R>>> {

	let mut obj_reader_map = HashMap::new();
	for obj_no in metadata.main_footer.object_footer.keys() {
		let obj_reader = initialize_object_reader(
			*obj_no,
			Arc::clone(&metadata))?;
		obj_reader_map.insert(*obj_no, obj_reader);
	}
	Ok(obj_reader_map)
}

fn initialize_object_reader<R: ReadAt>(
	object_number: u64, metadata: ArcZffReaderMetadata<R>) -> Result<ZffObjectReader<R>> {
	let segment_no_footer = match metadata.main_footer.object_footer.get(&object_number) {
		None => return Err(ZffError::new(
			ZffErrorKind::EncodingError,
			format!("{ERROR_MISSING_OBJECT_FOOTER_IN_SEGMENT}{object_number}"))),
		Some(segment_no) => segment_no
	};
	let segment_no_header = match metadata.main_footer.object_header.get(&object_number) {
		None => return Err(ZffError::new(
			ZffErrorKind::EncodingError, 
			format!("{ERROR_MISSING_OBJECT_HEADER_IN_SEGMENT}{object_number}"))),
		Some(segment_no) => segment_no
	};

	let encrypted = match metadata.segments.get(segment_no_header) {
		None => return Err(ZffError::new(
			ZffErrorKind::Missing, 
			segment_no_header.to_string())),
		Some(segment) => segment.read_object_header(object_number).is_err(),
	};
	if encrypted {
		initialize_encrypted_object_reader(
			object_number,
			*segment_no_header,
			*segment_no_footer,
			Arc::clone(&metadata))
	} else {
		initialize_unencrypted_object_reader(
			object_number,
			*segment_no_header,
			*segment_no_footer,
			Arc::clone(&metadata))
	}
}

fn initialize_unencrypted_object_reader<R: ReadAt>(
	obj_number: u64,
	header_segment_no: u64,
	footer_segment_no: u64,
	metadata: ArcZffReaderMetadata<R>,
	) -> Result<ZffObjectReader<R>> {
	#[cfg(feature = "log")]
	debug!("Initialize unencrypted object reader for object {obj_number}");
	let header = match metadata.segments.get(&header_segment_no) {
		None => return Err(ZffError::new(
			ZffErrorKind::Missing,
			format!("{ERROR_MISSING_SEGMENT}{header_segment_no}"))),
		Some(segment) => segment.read_object_header(obj_number)?,
	};
	let footer = match metadata.segments.get(&footer_segment_no) {
		None => return Err(ZffError::new(
			ZffErrorKind::Missing, 
			format!("{ERROR_MISSING_SEGMENT}{header_segment_no}"))),
		Some(segment) => segment.read_object_footer(obj_number)?,
	};
	let obj_number = header.object_number;
	let obj_metadata = ObjectMetadata::new(header, footer.clone());
	metadata
    .object_metadata
    .get(&obj_number)
    .ok_or_else(|| ZffError::new(ZffErrorKind::Missing, format!("{ERROR_MISSING_OBJECT_NO}{obj_number}")))?
    .set(obj_metadata)
    .map_err(|_| ZffError::new(ZffErrorKind::Invalid, format!("object already initialized: {obj_number}")))?;
	
	let obj_reader = match footer {
		ObjectFooter::Physical(_) => ZffObjectReader::Physical(Box::new(
			ZffObjectReaderPhysical::new(obj_number, Arc::clone(&metadata)))),
		ObjectFooter::Logical(_) => ZffObjectReader::Logical(Box::new(
			ZffObjectReaderLogical::new(obj_number, Arc::clone(&metadata))?)),
		ObjectFooter::Virtual(_) => ZffObjectReader::Virtual(Box::new(
			ZffObjectReaderVirtual::new(obj_number, Arc::clone(&metadata))?)),
	};
	#[cfg(feature = "log")]
	debug!("Object reader for object {obj_number} successfully initialized");
	Ok(obj_reader)
}

fn initialize_encrypted_object_reader<R: ReadAt>(
	obj_number: u64,
	header_segment_no: u64,
	footer_segment_no: u64,
	metadata: ArcZffReaderMetadata<R>,
	) -> Result<ZffObjectReader<R>> {

	let header = match metadata.segments.get(&header_segment_no) {
		None => return Err(ZffError::new(
			ZffErrorKind::Missing, 
			format!("{ERROR_MISSING_SEGMENT}{header_segment_no}"))),
		Some(segment) => segment.read_encrypted_object_header(obj_number)?,
	};
	let footer = match metadata.segments.get(&footer_segment_no) {
		None => return Err(ZffError::new(
			ZffErrorKind::Missing, 
			format!("{ERROR_MISSING_SEGMENT}{header_segment_no}"))),
		Some(segment) => segment.read_encrypted_object_footer(obj_number)?,
	};
	let obj_reader = ZffObjectReader::Encrypted(
		Box::new(ZffObjectReaderEncrypted::new(header, footer, Arc::clone(&metadata))));
	Ok(obj_reader)
}

fn preloaded_redb_chunk_header_map_add_entry(db: &mut Database, chunk_no: u64, chunk_header: ChunkHeader) -> Result<()> {
	let write_txn = db.begin_write()?;
	{
		let mut table_offset = write_txn.open_table(PRELOADED_CHUNK_OFFSET_MAP_TABLE)?;
		table_offset.insert(chunk_no, chunk_header.offset)?;
		
		let mut table_size = write_txn.open_table(PRELOADED_CHUNK_SIZE_MAP_TABLE)?;
		table_size.insert(chunk_no, chunk_header.size)?;

		let mut table_flags = write_txn.open_table(PRELOADED_CHUNK_FLAGS_MAP_TABLE)?;
		table_flags.insert(chunk_no, chunk_header.flags.as_bytes())?;

		let mut table_crc = write_txn.open_table(PRELOADED_CHUNK_XXHASH_MAP_TABLE)?;
		table_crc.insert(chunk_no, chunk_header.integrity_hash)?;
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

// tries to extract the appropriate ChunkHeader of the given chunk number.
// returns a None in case of error or if the chunkmap is a [PreloadedChunkmap::None].
fn extract_chunk_header_from_preloaded_chunkmap(preloaded_chunkmap: &PreloadedChunkMaps, chunk_number: u64) -> Option<ChunkHeader> {
	match preloaded_chunkmap {
		PreloadedChunkMaps::None => None,
		PreloadedChunkMaps::InMemory(preloaded_maps) => {
			preloaded_maps.chunk_header.get(&chunk_number).cloned() //TODO: find a more efficient way?
		},
		PreloadedChunkMaps::Redb(db) => {
			let read_txn = db.begin_read().ok()?;
    		let table = read_txn.open_table(PRELOADED_CHUNK_OFFSET_MAP_TABLE).ok()?;
    		let offset = table.get(&chunk_number).ok()??.value();
    		
			let read_txn = db.begin_read().ok()?;
    		let table = read_txn.open_table(PRELOADED_CHUNK_SIZE_MAP_TABLE).ok()?;
    		let size = table.get(&chunk_number).ok()??.value();

			let read_txn = db.begin_read().ok()?;
    		let table = read_txn.open_table(PRELOADED_CHUNK_FLAGS_MAP_TABLE).ok()?;
    		let flags = table.get(&chunk_number).ok()??.value().into();
    		
			let read_txn = db.begin_read().ok()?;
    		let table = read_txn.open_table(PRELOADED_CHUNK_XXHASH_MAP_TABLE).ok()?;
    		let integrity_hash = table.get(&chunk_number).ok()??.value();

			Some(ChunkHeader::new(offset, size, flags, integrity_hash))
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
			Some(value)
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
    		Some(value)
		}
	}
}

fn get_chunks_of_unencrypted_object<R: ReadAt>(
	object_reader: &HashMap<u64, ZffObjectReader<R>>, 
	object_number: u64) -> Result<Vec<u64>> { //TODO-Check: Return a Range for better performance?
	let obj_reader = match object_reader.get(&object_number) {
		Some(reader) => reader,
		None => return Err(ZffError::new(
			ZffErrorKind::Missing, 
			format!("{ERROR_MISSING_OBJECT_NO}{object_number}"))),
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
				// unwrap is safe here: you cannot initialize a ZffObjectReaderLogical with a [VirtualFileFooter].
				let first_chunk_no = filemetadata.first_chunk_number().unwrap();
				let last_chunk_no = filemetadata.number_of_chunks().unwrap() + first_chunk_no - 1;
				chunk_numbers.extend(first_chunk_no..=last_chunk_no);
			}
			chunk_numbers
		},
		ZffObjectReader::Virtual(_) => {
			//TODO: not sure if I should return chunk numbers...I'll skip this and check this later
			Vec::new()
		},
		ZffObjectReader::Encrypted(_) => {
			return Err(ZffError::new(
				ZffErrorKind::EncryptionError, 
				ERROR_MISSING_ENCRYPTION_HEADER_KEY));
		},
	};

	Ok(chunk_numbers)
}

fn get_enc_info_from_obj_reader<R: ReadAt>(object_reader: &ZffObjectReader<R>) -> Result<Option<EncryptionInformation>> {
		let enc_info = match object_reader {
		ZffObjectReader::Physical(reader) => EncryptionInformation::try_from(reader.object_header_ref()),
		ZffObjectReader::Virtual(reader) => EncryptionInformation::try_from(reader.object_header_ref()),
		ZffObjectReader::Logical(reader) => EncryptionInformation::try_from(reader.object_header_ref()),
		ZffObjectReader::Encrypted(_) => return Err(ZffError::new(
			ZffErrorKind::EncryptionError, 
			ERROR_MISSING_ENCRYPTION_HEADER_KEY)),
	};
	let enc_info = match enc_info {
		Ok(enc_info) => Some(enc_info),
		Err(e) => match e.kind_ref() {
			ZffErrorKind::EncryptionError => None,
			_ => return Err(e),
		},
	};
	Ok(enc_info)
}

fn initialize_new_map_if_empty<R: ReadAt>(metadata: ArcZffReaderMetadata<R>) {
	let mut preloaded_chunkmaps = metadata.preloaded_chunkmaps.write().unwrap();
	let new_preloaded_chunkmaps = match *preloaded_chunkmaps {
		PreloadedChunkMaps::None => {
			PreloadedChunkMaps::InMemory(PreloadedChunkMapsInMemory {
				..Default::default()
			})
		},
		_ => return,
	};
	*preloaded_chunkmaps = new_preloaded_chunkmaps;
}

/// Returns the segment number and the appropriate offset of a chunkmap 
/// (if exists for the appropriate chunk number).
/// Otherwise, returns None.
fn chunkmap_offset_info<R>(
	chunkmap_type: ChunkMapType, 
	chunk_number: u64, 
	metadata: &ArcZffReaderMetadata<R>) -> Option<(u64 ,u64)>
where 
	R: ReadAt,	
{
	let segment_no = match chunkmap_type {
		ChunkMapType::HeaderMap => metadata.main_footer.chunk_header_maps.get(&chunk_number)?,
		ChunkMapType::SamebytesMap => metadata.main_footer.chunk_samebytes_maps().get(&chunk_number)?,
		ChunkMapType::DeduplicationMap => metadata.main_footer.chunk_dedup_maps().get(&chunk_number)?,
	};
	let offset = match chunkmap_type {
		ChunkMapType::HeaderMap => metadata.segments.get(segment_no)?.footer().chunk_header_map_table.get(&chunk_number),
		ChunkMapType::SamebytesMap => metadata.segments.get(segment_no)?.footer().chunk_samebytes_map_table.get(&chunk_number),
		ChunkMapType::DeduplicationMap => metadata.segments.get(segment_no)?.footer().chunk_dedup_map_table.get(&chunk_number),
	};
	offset.map(|value| (*segment_no, *value))
}
