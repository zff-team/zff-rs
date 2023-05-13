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
	HEADER_IDENTIFIER_CHUNK_MAP,
	DEFAULT_HEADER_VERSION_CHUNK_MAP,
	CHUNKMAP_SQLITE_CREATE_TABLE_IFNOTEXISTS,
	CHUNKMAP_SQLITE_INSERT_INTO_MAP,
	CHUNKMAP_SQLITE_SELECT_BY_B3HASH,
	CHUNKMAP_SQLITE_CHUNK_NO_IDENTIFIER,
	CHUNKMAP_SQLITE_B3HASH_IDENTIFIER,
};

// - external
use rusqlite::Connection as SqliteConnection;
use blake3::Hash as Blake3Hash;

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct ChunkMap {
	pub version: u8,
	pub chunkmap: BTreeMap<u64, u64>, //<chunk no, offset in segment>
	target_size: usize,
}

impl ChunkMap {
	/// returns a new [ChunkMap] with the given values.
	pub fn new(chunkmap: BTreeMap<u64, u64>) -> Self {
		Self {
			version: DEFAULT_HEADER_VERSION_CHUNK_MAP,
			chunkmap,
			target_size: 0,
		}
	}

	/// returns a new, empty [ChunkMap] with the given values.
	pub fn new_empty() -> Self {
		Self {
			version: DEFAULT_HEADER_VERSION_CHUNK_MAP,
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
		self.version
	}
	
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.append(&mut self.version.encode_directly());
		vec.append(&mut self.chunkmap.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		let _version = u8::decode_directly(&mut cursor)?; // TODO: return an unsupported header version, if the version does not match with the current version.
		let chunkmap = BTreeMap::<u64, u64>::decode_directly(&mut cursor)?;
		Ok(Self::new(chunkmap))
	}
}

pub enum DeduplicationChunkMap {
	InMemory(HashMap<Blake3Hash, u64>), //<blake3-hash, the appropriate chunk number with the original data>
	TempSqlite(SqliteConnection),
}

impl Default for DeduplicationChunkMap {
	fn default() -> Self {
		DeduplicationChunkMap::InMemory(HashMap::new())
	}
}

impl DeduplicationChunkMap {
	pub fn new_from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
		let db_conn = SqliteConnection::open(
			path.as_ref())?;
		db_conn.execute(CHUNKMAP_SQLITE_CREATE_TABLE_IFNOTEXISTS, ())?;
        Ok(Self::TempSqlite(db_conn))
	}

	pub fn new_from_sqlite_connection(connection: SqliteConnection) -> Self {
		Self::TempSqlite(connection)
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
			DeduplicationChunkMap::TempSqlite(conn) => {
				let statement = String::from(CHUNKMAP_SQLITE_INSERT_INTO_MAP)
								.replace(CHUNKMAP_SQLITE_CHUNK_NO_IDENTIFIER, &chunk_no.to_string())
				 				.replace(CHUNKMAP_SQLITE_B3HASH_IDENTIFIER, &blak3_hash.to_hex());
				conn.execute(&statement, ())?;
				Ok(())
			}
		}
	}

	#[allow(clippy::let_and_return)]
	pub fn get_chunk_number<B>(&mut self, blak3_hash: B) -> Option<u64>
	where
		B: Borrow<Blake3Hash>
	{ //returns the appropriate Chunk no.
		match self {
			DeduplicationChunkMap::InMemory(map) => {
				map.get(blak3_hash.borrow()).copied()
			},
			DeduplicationChunkMap::TempSqlite(conn) => {
				let number: u64 = conn.query_row(&String::from(CHUNKMAP_SQLITE_SELECT_BY_B3HASH)
												.replace(CHUNKMAP_SQLITE_B3HASH_IDENTIFIER, 
													&blak3_hash.borrow().to_hex()), 
												[],
												|row| row.get(0)).ok()?;
				Some(number)
			}
		}
	}
}