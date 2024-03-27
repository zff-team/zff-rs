// - STD
use core::borrow::Borrow;
use std::path::Path;
use std::cmp::PartialEq;
use std::collections::{HashMap, BTreeMap};
use std::io::Cursor;
use std::fmt;

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	ZffError,
	HEADER_IDENTIFIER_CHUNK_MAP,
	DEFAULT_HEADER_VERSION_CHUNK_MAP,
	CHUNK_MAP_TABLE,
};

#[cfg(feature = "serde")]
use crate::helper::string_to_str;

// - external
use redb::{Database, ReadableTable};
use blake3::Hash as Blake3Hash;
#[cfg(feature = "serde")]
use serde::{
	Deserialize,
	Serialize,
	ser::{Serializer, SerializeStruct},
};
#[cfg(feature = "serde")]
use hex;

/// The Chunkmap stores the information where the each appropriate chunk could be found.
#[derive(Debug,Clone,PartialEq,Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct ChunkMap {
	chunkmap: BTreeMap<u64, u64>, //<chunk no, offset in segment>
	target_size: usize,
}

impl ChunkMap {
	/// returns a new [ChunkMap] with the given values.
	pub fn with_data(chunkmap: BTreeMap<u64, u64>) -> Self {
		Self {
			chunkmap,
			target_size: 0,
		}
	}

	/// Returns a reference to the inner map
	pub fn chunkmap(&self) -> &BTreeMap<u64, u64> {
		&self.chunkmap
	}

	/// The encoded size of this map.
	pub fn current_size(&self) -> usize {
		self.chunkmap.len() * 16 + 8
	}

	/// returns a new, empty [ChunkMap] with the given values.
	pub fn new_empty() -> Self {
		Self {
			chunkmap: BTreeMap::new(),
			target_size: 0,
		}
	}

	/// Reset the target size to the given value.
	pub fn set_target_size(&mut self, target_size: usize) {
		self.target_size = target_size
	}

	/// Tries to add a chunk entry.  
	/// Returns true, if the chunk no / offset pair was added to the map.  
	/// Returns false, if the map is full (in this case, the pair was **not** added to the map).
	pub fn add_chunk_entry(&mut self, chunk_no: u64, offset: u64) -> bool {
		if self.is_full() { //24 -> 8bytes for next chunk_no, 8bytes for next offset, 8 bytes for the size of the encoded BTreeMap
			false
		} else {
			self.chunkmap.entry(chunk_no).or_insert(offset);
			true
		}
	}

	/// Checks if the map is full (returns true if, returns false if not).
	pub fn is_full(&self) -> bool {
		if self.target_size < self.current_size() + 24 { //24 -> 8bytes for next chunk_no, 8bytes for next offset, 8 bytes for the size of the encoded BTreeMap
			true
		} else {
			false
		}
	}

	/// Returns the inner map and replaces it with an empty map.
	pub fn flush(&mut self) -> BTreeMap<u64, u64> {
		std::mem::take(&mut self.chunkmap)
	}
}

impl HeaderCoding for ChunkMap {
	type Item = ChunkMap;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_CHUNK_MAP
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_CHUNK_MAP
	}
	
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.append(&mut Self::version().encode_directly());
		vec.append(&mut self.chunkmap.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?;
		let chunkmap = BTreeMap::<u64, u64>::decode_directly(&mut cursor)?;
		Ok(Self::with_data(chunkmap))
	}
}

// - implement fmt::Display
impl fmt::Display for ChunkMap {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl ChunkMap {
	fn struct_name(&self) -> &'static str {
		"ChunkMap"
	}
}

#[cfg(feature = "serde")]
impl Serialize for ChunkMap {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct(self.struct_name(), 2)?;
        state.serialize_field("target-size", &self.target_size)?;
        for (key, value) in &self.chunkmap {
        	state.serialize_field(string_to_str(key.to_string()), &value)?;
        }
        state.end()
    }
}


/// A map which can be used to handle the chunk deduplication.
#[derive(Debug)]
pub enum DeduplicationChunkMap {
	/// Use a in-memory deduplication map at cost of memory.
	InMemory(HashMap<Blake3Hash, u64>), //<blake3-hash, the appropriate chunk number with the original data>
	/// Use a Redb based deduplication map at cost of I/O.
	Redb(Database),
}

impl Default for DeduplicationChunkMap {
	fn default() -> Self {
		DeduplicationChunkMap::InMemory(HashMap::new())
	}
}

impl DeduplicationChunkMap {
	/// Creates a new [DeduplicationChunkMap] with a Redb by given path.
	/// May fail if the Redb can not be created at the given Path.
	pub fn new_from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
		let db = Database::create(path.as_ref())?;
        Ok(Self::Redb(db))
	}

	/// Creates a new [DeduplicationChunkMap] with the given [Redb-Database](crate::redb::Database).
	pub fn new_from_db(database: Database) -> Self {
		Self::Redb(database)
	}

	/// Creates a new in-memory [DeduplicationChunkMap].
	pub fn new_in_memory_map() -> Self {
		DeduplicationChunkMap::InMemory(HashMap::new())
	}

	/// Adds an entry to the deduplication map.
	pub fn append_entry(&mut self, chunk_no: u64, blak3_hash: Blake3Hash) -> Result<()> {
		match self {
			DeduplicationChunkMap::InMemory(map) => {
				match map.get_mut(&blak3_hash) {
					Some(_) => (),
					None => { map.insert(blak3_hash, chunk_no); }
				}
				Ok(())
			},
			DeduplicationChunkMap::Redb(db) => {
				let write_txn = db.begin_write()?;
			    {
			        let mut table = write_txn.open_table(CHUNK_MAP_TABLE)?;
			        table.insert(blak3_hash.as_bytes(), chunk_no)?;
			    }
			    write_txn.commit()?;
				Ok(())
			}
		}
	}

	/// Returns the chunk number to the given hash.
	pub fn get_chunk_number<B>(&mut self, blak3_hash: B) -> Result<u64>
	where
		B: Borrow<Blake3Hash>
	{ //returns the appropriate Chunk no.
		match self {
			DeduplicationChunkMap::InMemory(map) => {
				map.get(blak3_hash.borrow()).copied().ok_or(ZffError::new_not_in_map_error())
			},
			DeduplicationChunkMap::Redb(db) => {
			let read_txn = db.begin_read()?;
    		let table = read_txn.open_table(CHUNK_MAP_TABLE)?;
    		let value = table.get(blak3_hash.borrow().as_bytes())?.ok_or(ZffError::new_not_in_map_error())?.value();
    		Ok(value)
			}
		}
	}
}

#[cfg(feature = "serde")]
impl Serialize for DeduplicationChunkMap {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct(self.struct_name(), 6)?;
        let mut ser_dedup_map = HashMap::new();
        match self {
        	DeduplicationChunkMap::InMemory(dedup_map) => {
        		for (blake3_hash, chunk_number) in dedup_map {
        			ser_dedup_map.insert(blake3_hash.to_hex().to_lowercase(), *chunk_number);
        		};
        		state.serialize_field("in-memory-map", &ser_dedup_map)?;
        	},
        	DeduplicationChunkMap::Redb(database) => {
        		let read_txn = match database.begin_read() {
        			Ok(txn) => txn,
        			Err(e) => return Err(serde::ser::Error::custom(e.to_string())),
        		};
        		let table = match read_txn.open_table(CHUNK_MAP_TABLE) {
        			Ok(table) => table,
        			Err(e) => return Err(serde::ser::Error::custom(e.to_string())),
        		};
        		let iterator = match table.iter() {
        			Ok(iterator) => iterator,
        			Err(e) => return Err(serde::ser::Error::custom(e.to_string())),
        		};

        		for element in iterator {
        			let (k, v) = match element {
	        			Ok((k, v)) => (k, v),
	        			Err(e) => return Err(serde::ser::Error::custom(e.to_string())),
	        		};
        			ser_dedup_map.insert(hex::encode(k.value()), v.value());
        		};
        		state.serialize_field("redb-map", &ser_dedup_map)?;
        	}
        }
        state.end()
    }
}


// - implement fmt::Display
impl fmt::Display for DeduplicationChunkMap {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl DeduplicationChunkMap {
	fn struct_name(&self) -> &'static str {
		"DeduplicationChunkMap"
	}
}