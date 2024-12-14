// - parent
use super::*;

// - internal
use crate::{
    HEADER_IDENTIFIER_CHUNK_SAMEBYTES_MAP,
	DEFAULT_HEADER_VERSION_CHUNK_SAMEBYTES_MAP,
};

/// The [ChunkSamebytesMap] stores the chunk size of the appropriate chunk.
#[derive(Debug,Clone,PartialEq,Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct ChunkSamebytesMap {
	chunkmap: BTreeMap<u64, u8>, //<chunk no, chunk size in segment>
	target_size: usize,
}

impl Default for ChunkSamebytesMap {
	fn default() -> Self {
		Self::new_empty()
	}
}

impl ChunkMap for ChunkSamebytesMap {
	type Value = u8;

	/// returns a new [ChunkOffsetMap] with the given values.
	fn with_data(chunkmap: BTreeMap<u64, Self::Value>) -> Self {
		Self {
			chunkmap,
			target_size: 0,
		}
	}

	/// returns a new, empty [ChunkOffsetMap] with the given values.
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
			Some(_) => self.chunkmap.len() * (8 + 1) + 8, //8 -> 8bytes for the chunk no, 1 byte for samebyte
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
		if self.target_size < self.current_size() + 17 { 
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
		let enc_buffer = Encryption::decrypt_chunk_samebytes_map(key, structure_data, chunk_no, encryption_algorithm.borrow())?;
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
		vec.append(&mut Self::encode_map(self));
		let enc_buffer = Encryption::encrypt_chunk_samebytes_map(key, vec, chunk_no, encryption_algorithm.borrow())?;
		Ok(enc_buffer)
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
		vec.append(&mut self.chunkmap.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?;
		let chunkmap = BTreeMap::<u64, u8>::decode_directly(&mut cursor)?;
		Ok(Self::with_data(chunkmap))
	}
}

// - implement fmt::Display
impl fmt::Display for ChunkSamebytesMap {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl ChunkSamebytesMap {
	fn struct_name(&self) -> &'static str {
		"ChunkSamebytesMap"
	}
}

#[cfg(feature = "serde")]
impl Serialize for ChunkSamebytesMap {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct(self.struct_name(), 2)?;
        for (key, value) in &self.chunkmap {
        	state.serialize_field(string_to_str(key.to_string()), &value)?;
        }
        state.end()
    }
}