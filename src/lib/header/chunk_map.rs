// - STD
use core::borrow::Borrow;
use std::path::Path;
use std::cmp::{PartialEq};
use std::collections::{HashMap, BTreeMap};
use std::io::{Cursor};

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	ZffError,
	ZffErrorKind,
	HEADER_IDENTIFIER_CHUNK_MAP,
	DEFAULT_HEADER_VERSION_CHUNK_MAP,
	CHUNK_MAP_TABLE,
};

// - external
use redb::{Database, ReadableTable};
use blake3::Hash as Blake3Hash;

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct ChunkMap {
	pub chunkmap: BTreeMap<u64, u64>, //<chunk no, offset in segment>
	target_size: usize,
}

impl ChunkMap {
	/// returns a new [ChunkMap] with the given values.
	pub fn new(chunkmap: BTreeMap<u64, u64>) -> Self {
		Self {
			chunkmap,
			target_size: 0,
		}
	}

	/// returns a new, empty [ChunkMap] with the given values.
	pub fn new_empty() -> Self {
		Self {
			chunkmap: BTreeMap::new(),
			target_size: 0,
		}
	}

	pub fn set_target_size(&mut self, target_size: usize) {
		self.target_size = target_size
	}

	pub fn add_chunk_entry(&mut self, chunk_no: u64, offset: u64) -> bool {
		if self.target_size < self.chunkmap.len() + 24 { //24 -> 8bytes for next chunk_no, 8bytes for next offset, 8 bytes for the size of the encoded BTreeMap
			false
		} else {
			self.chunkmap.insert(chunk_no, offset);
			true
		}
	}

	pub fn flush(&mut self) -> BTreeMap<u64, u64> {
		std::mem::take(&mut self.chunkmap)
	}
}

impl HeaderCoding for ChunkMap {
	type Item = ChunkMap;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_CHUNK_MAP
	}

	fn version(&self) -> u8 {
		DEFAULT_HEADER_VERSION_CHUNK_MAP
	}
	
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.append(&mut self.version().encode_directly());
		vec.append(&mut self.chunkmap.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		let version = u8::decode_directly(&mut cursor)?;
		if version != DEFAULT_HEADER_VERSION_CHUNK_MAP {
			return Err(ZffError::new(ZffErrorKind::UnsupportedVersion, version.to_string()))
		};
		let chunkmap = BTreeMap::<u64, u64>::decode_directly(&mut cursor)?;
		Ok(Self::new(chunkmap))
	}
}

pub enum DeduplicationChunkMap {
	InMemory(HashMap<Blake3Hash, u64>), //<blake3-hash, the appropriate chunk number with the original data>
	Redb(Database),
}

impl Default for DeduplicationChunkMap {
	fn default() -> Self {
		DeduplicationChunkMap::InMemory(HashMap::new())
	}
}

impl DeduplicationChunkMap {
	pub fn new_from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
		let db = Database::create(path.as_ref())?;
        Ok(Self::Redb(db))
	}

	pub fn new_from_db(database: Database) -> Self {
		Self::Redb(database)
	}

	pub fn new_in_memory_map() -> Self {
		DeduplicationChunkMap::InMemory(HashMap::new())
	}

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

	#[allow(clippy::let_and_return)]
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