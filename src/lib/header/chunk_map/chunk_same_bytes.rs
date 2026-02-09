// - parent
use super::*;

/// The [ChunkSamebytesMap] stores the chunk size of the appropriate chunk.
#[derive(Debug,Clone,PartialEq,Eq, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct ChunkSamebytesMap {
	chunkmap: BTreeMap<u64, u8>, //<chunk no, chunk size in segment>
	object_number: u64,
	target_size: usize,
}

impl ChunkMap for ChunkSamebytesMap {
	type Value = u8;

	/// returns a new [ChunkOffsetMap] with the given values.
	fn new(object_number: u64, chunkmap: BTreeMap<u64, Self::Value>) -> Self {
		Self {
			chunkmap,
			object_number,
			target_size: 0,
		}
	}

	/// returns a new, empty [ChunkOffsetMap] with the given values.
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
			Some(_) => self.chunkmap.len() * (8 + 1) + 8, //8 -> 8bytes for the chunk no, 1 byte for samebyte
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
			self.chunkmap.entry(chunk_no).or_insert(*value.borrow());
			true
		}
	}

	fn is_full(&self) -> bool {
		if self.target_size < self.current_size() + 17 { 
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

impl HeaderCoding for ChunkSamebytesMap {
	type Item = ChunkSamebytesMap;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_CHUNK_SAMEBYTES_MAP
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_CHUNK_SAMEBYTES_MAP
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
		let chunkmap = BTreeMap::<u64, u8>::decode_directly(&mut cursor)?;
		Ok(Self::new(object_number, chunkmap))
	}

	fn struct_name() -> &'static str {
		"ChunkSamebytesMap"
	}
}

// - implement fmt::Display
impl fmt::Display for ChunkSamebytesMap {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", Self::struct_name())
	}
}

impl Encryption for ChunkSamebytesMap {
	fn crypto_nonce_padding() -> u8 {
		0b00011111
	}
}

#[cfg(feature = "serde")]
impl Serialize for ChunkSamebytesMap {
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