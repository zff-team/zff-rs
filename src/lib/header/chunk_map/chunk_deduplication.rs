// - parent
use super::*;

// - internal
use crate::{
	io::zffreader::ZffReader,
    HEADER_IDENTIFIER_CHUNK_DEDUPLICATION_MAP,
	DEFAULT_HEADER_VERSION_CHUNK_DEDUPLICATION_MAP,
	CHUNK_MAP_TABLE,
};

// - external
use redb::Database;
use blake3::Hash as Blake3Hash;

/// The [ChunkDeduplicationMap] stores the chunk size of the appropriate chunk.
#[derive(Debug,Clone,PartialEq,Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct ChunkDeduplicationMap {
	chunkmap: BTreeMap<u64, u64>, //<chunk no, dedup chunk no>
	target_size: usize,
}

impl Default for ChunkDeduplicationMap {
	fn default() -> Self {
		Self::new_empty()
	}
}

impl ChunkMap for ChunkDeduplicationMap {
	type Value = u64;

	/// returns a new [ChunkDeduplicationMap] with the given values.
	fn with_data(chunkmap: BTreeMap<u64, Self::Value>) -> Self {
		Self {
			chunkmap,
			target_size: 0,
		}
	}

	/// returns a new, empty [ChunkDeduplicationMap] with the given values.
	fn new_empty() -> Self {
		Self {
			chunkmap: BTreeMap::new(),
			target_size: 0,
		}
	}

	fn flush(&mut self) -> BTreeMap<u64, Self::Value> {
		std::mem::take(&mut self.chunkmap)
	}

	fn current_size(&self) -> usize {
		match self.chunkmap.first_key_value() {
			Some(_) => self.chunkmap.len() * (8 + 8) + 8, //8 -> 8bytes for the chunk no, 8 bytes for the deduplication chunk no
			None => return 0,
		}
	}

	fn chunkmap(&self) -> &BTreeMap<u64, Self::Value> {
		&self.chunkmap
	}

	fn set_target_size(&mut self, target_size: usize) {
		self.target_size = target_size
	}

	fn add_chunk_entry<V: Borrow<Self::Value>>(&mut self, chunk_no: u64, value: V) -> bool {
		if self.is_full() {
			false
		} else {
			self.chunkmap.entry(chunk_no).or_insert(*value.borrow());
			true
		}
	}

	fn is_full(&self) -> bool {
		if self.target_size < self.current_size() + 24 { //24 -> 8bytes for next chunk_no, 8 bytes for deduplication chunk_no, 8 bytes for the size of the encoded BTreeMap
			true
		} else {
			false
		}
	}

	fn decrypt_and_decode<K, A, D>(key: K, encryption_algorithm: A, data: &mut D, chunk_no: u64) -> Result<Self> 
    where
    K: AsRef<[u8]>, 
    A: Borrow<EncryptionAlgorithm>, 
    D: Read,
    Self: Sized {
		let structure_data = Self::inner_structure_data(data)?;
		let enc_buffer = ChunkDeduplicationMap::decrypt(key, structure_data, chunk_no, encryption_algorithm.borrow())?;
		let mut reader = Cursor::new(enc_buffer);
		let map = BTreeMap::decode_directly(&mut reader)?;
		Ok(Self::with_data(map))
	}

	fn encode_map(&self) -> Vec<u8> {
		self.chunkmap.encode_directly()
	}

	fn encrypt_encoded_map<K, A>(&self, key: K, encryption_algorithm: A, chunk_no: u64) -> Result<Vec<u8>>
		where
		K: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
		Self: HeaderCoding, {
		let mut vec = Vec::new();
		let encoded_map = Self::encode_map(self);
		let mut encrypted_map = Self::encrypt(key, encoded_map, chunk_no, encryption_algorithm.borrow())?;
		let mut encoded_version = Self::version().encode_directly();
		let identifier = Self::identifier();
		let encoded_header_length = (
			DEFAULT_LENGTH_HEADER_IDENTIFIER + 
			DEFAULT_LENGTH_VALUE_HEADER_LENGTH + 
			encrypted_map.len() +
			encoded_version.len()) as u64;
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.append(&mut encoded_version);
		vec.append(&mut encrypted_map);
		Ok(vec)
	}
}

impl HeaderCoding for ChunkDeduplicationMap {
	type Item = ChunkDeduplicationMap;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_CHUNK_DEDUPLICATION_MAP
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_CHUNK_DEDUPLICATION_MAP
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

	fn struct_name() -> &'static str {
		"ChunkDeduplicationMap"
	}
}

// - implement fmt::Display
impl fmt::Display for ChunkDeduplicationMap {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", Self::struct_name())
	}
}

impl Encryption for ChunkDeduplicationMap {
	fn crypto_nonce_padding() -> u8 {
		0b00111111
	}
}

#[cfg(feature = "serde")]
impl Serialize for ChunkDeduplicationMap {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct(Self::struct_name(), 2)?;
        for (key, value) in &self.chunkmap {
        	state.serialize_field(string_to_str(key.to_string()), &value)?;
        }
        state.end()
    }
}

/// A structure to handle chunk deduplication.
#[derive(Debug, Default)]
pub struct DeduplicationMetadata<R: Read + Seek> {
	/// A map which can be used to handle the chunk deduplication.
	pub deduplication_map: DeduplicationChunkMap,
	/// Optional original zffreader - in case of an extension of an existing zff container.
	pub original_zffreader: Option<ZffReader<R>>,
}

//TODO: use xxhash before using blake3
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

	/// Creates a new [DeduplicationChunkMap] with the given [Redb-Database](Database).
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
        let mut state = serializer.serialize_struct(Self::struct_name(), 6)?;
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
		write!(f, "{}", Self::struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl DeduplicationChunkMap {
	fn struct_name() -> &'static str {
		"DeduplicationChunkMap"
	}
}