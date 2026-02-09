// - parent
use super::{*, io::zffreader::ZffReader};

/// The [ChunkDeduplicationMap] stores the chunk size of the appropriate chunk.
#[derive(Debug,Clone,PartialEq,Eq, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct ChunkDeduplicationMap {
	chunkmap: BTreeMap<u64, u64>, //<chunk no, dedup chunk no>
	object_number: u64,
	target_size: usize,
}

impl ChunkMap for ChunkDeduplicationMap {
	type Value = u64;

	/// returns a new [ChunkDeduplicationMap] with the given values.
	fn new(object_number: u64, chunkmap: BTreeMap<u64, Self::Value>) -> Self {
		Self {
			chunkmap,
			object_number,
			target_size: 0,
		}
	}

	/// returns a new, empty [ChunkDeduplicationMap] with the given values.
	fn new_empty(object_number: u64) -> Self {
		Self {
			chunkmap: BTreeMap::new(),
			object_number,
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

	fn object_number(&self) -> u64 {
		self.object_number
	}

	fn append(&mut self, mut map: Self) {
		self.chunkmap.append(&mut map.flush());
	}

	fn set_target_size(&mut self, target_size: usize) {
		self.target_size = target_size
	}

	fn set_object_number(&mut self, object_number: u64) {
		self.object_number = object_number
	}

	fn add_chunk_entry(&mut self, chunk_no: u64, value: Self::Value) -> bool {
		if self.is_full() {
			false
		} else {
			self.chunkmap.entry(chunk_no).or_insert(value);
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

	fn is_empty(&self) -> bool {
		self.chunkmap.is_empty()
	}

	fn decrypt_and_decode<K, A, D>(key: K, encryption_algorithm: A, data: &mut D, chunk_no: u64) -> Result<Self> 
    where
    K: AsRef<[u8]>, 
    A: Borrow<EncryptionAlgorithm>, 
    D: Read,
    Self: Sized {
		let inner_structure_data = Self::inner_structure_data(data)?;
		let enc_buffer = Self::decrypt(key, inner_structure_data.structure_data, chunk_no, encryption_algorithm.borrow())?;
		let mut reader = Cursor::new(enc_buffer);
		let map = BTreeMap::decode_directly(&mut reader)?;
		Ok(Self::new(inner_structure_data.object_number, map))
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
		let mut encoded_object_number = self.object_number.encode_directly();
		let identifier = Self::identifier();
		let encoded_header_length = (
			DEFAULT_LENGTH_HEADER_IDENTIFIER + 
			DEFAULT_LENGTH_VALUE_HEADER_LENGTH + 
			encoded_object_number.len() +
			encrypted_map.len() +
			encoded_version.len()) as u64;
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.append(&mut encoded_version);
		vec.append(&mut encoded_object_number);
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
		vec.append(&mut self.object_number.encode_directly());
		vec.append(&mut self.chunkmap.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?;
		let object_number = u64::decode_directly(&mut cursor)?;
		let chunkmap = BTreeMap::<u64, u64>::decode_directly(&mut cursor)?;
		Ok(Self::new(object_number, chunkmap))
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
	/// Optional original zffreader - in case of an extension of an existing zff container, this is necessary.
	pub original_zffreader: Option<ZffReader<R>>,
}

/// A map which can be used to handle the chunk deduplication.
#[derive(Debug)]
pub enum DeduplicationChunkMap {
	/// Use a in-memory deduplication map at cost of memory.
	InMemory(InMemoryDedupMap), //<xxhash, the appropriate chunk number with the original data>
	/// Use a Redb based deduplication map at cost of I/O.
	Redb(Database),
}

impl Default for DeduplicationChunkMap {
	fn default() -> Self {
		DeduplicationChunkMap::InMemory(InMemoryDedupMap::default())
	}
}

/// The InMemory deduplication map structure
#[derive(Debug, Default)]
pub struct InMemoryDedupMap {
	xxhash_map: HashMap<u64, HashSet<u64>>, //<xxhash-value, HashSet<Chunk-No>
	verification_hash_map: HashMap<u64, Blake3Hash> // Chunk-No, Verification-Hash
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
		DeduplicationChunkMap::InMemory(InMemoryDedupMap::default())
	}

	/// Adds an entry to the deduplication map.
	pub fn append_entry(&mut self, xxhash: u64, chunk_no: u64) -> Result<()> {
		match self {
			DeduplicationChunkMap::InMemory(map) => {
				//TODO: Better implementation in future with get_or_insert
				// see: https://github.com/rust-lang/rust/issues/60896
				match map.xxhash_map.get_mut(&xxhash) {
					Some(set) => { set.insert(chunk_no); },
					None => {
						let mut set = HashSet::new();
						set.insert(chunk_no);
						map.xxhash_map.insert(xxhash, set);
					}
				}
				Ok(())
			},
			DeduplicationChunkMap::Redb(db) => {
				let read_txn = db.begin_read()?;
				let table = read_txn.open_table(CHUNK_MAP_TABLE)?;
				let mut inner_vec = table.get(xxhash)?.ok_or(
					ZffError::new(ZffErrorKind::NotFound, ERROR_NOT_IN_MAP))?.value();
				if !inner_vec.contains(&chunk_no) {
					inner_vec.push(chunk_no);
				};
				let write_txn = db.begin_write()?;
			    {
			        let mut table = write_txn.open_table(CHUNK_MAP_TABLE)?;
			        table.insert(xxhash, inner_vec)?;
			    }
			    write_txn.commit()?;
				Ok(())
			}
		}
	}

	/// Adds a blake3 hash to an existing chunk / xxhash combination
	pub fn append_verification_hash<B: Borrow<Blake3Hash>>(&mut self, chunk_no: u64, verification_hash: B) -> Result<()> {
		match self {
			DeduplicationChunkMap::InMemory(map) => {
				map.verification_hash_map.insert(chunk_no, *verification_hash.borrow());
				Ok(())
			},
			DeduplicationChunkMap::Redb(db) => {
				let write_txn = db.begin_write()?;
			    {
			        let mut table = write_txn.open_table(CHUNK_MAP_B3_TABLE)?;
			        table.insert(chunk_no, verification_hash.borrow().as_bytes())?;
			    }
			    write_txn.commit()?;
				Ok(())
			}
		}
	}

	/// Returns all chunk numbers to the given xxhash.
	pub fn get_chunk_number(&mut self, xxhash: u64) -> Result<HashSet<u64>> {
		match self {
			DeduplicationChunkMap::InMemory(map) => {
				map.xxhash_map.get(&xxhash).ok_or(ZffError::new(
					ZffErrorKind::NotFound, ERROR_NOT_IN_MAP)).map(|map| map.clone())
			},
			DeduplicationChunkMap::Redb(db) => {
			let read_txn = db.begin_read()?;
    		let table = read_txn.open_table(CHUNK_MAP_TABLE)?;
    		let inner_vec = table.get(xxhash)?.ok_or(
				ZffError::new(ZffErrorKind::NotFound, ERROR_NOT_IN_MAP))?.value();
			Ok(inner_vec.into_iter().collect())
			}
		}
	}

	/// Returns the appropriate verification Hash, if exists
	pub fn get_verification_hash(&mut self, chunk_no: u64) -> Result<Option<Blake3Hash>> {
		match self {
			DeduplicationChunkMap::InMemory(map) => {
				Ok(map.verification_hash_map.get(&chunk_no).map(|hash| hash.clone()))
			},
			DeduplicationChunkMap::Redb(db) => {
				let read_txn = db.begin_read()?;
				let table = read_txn.open_table(CHUNK_MAP_B3_TABLE)?;
				Ok(table.get(chunk_no)?.map(|access_guard| Blake3Hash::from_bytes(*access_guard.value())))
			}
		}
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