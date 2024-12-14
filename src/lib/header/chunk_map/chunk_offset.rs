// - parent
use super::*;

// - internal
use crate::{
    HEADER_IDENTIFIER_CHUNK_OFFSET_MAP,
	DEFAULT_HEADER_VERSION_CHUNK_OFFSET_MAP,
};

/// The Chunkmap stores the information where the each appropriate chunk could be found.
#[derive(Debug,Clone,PartialEq,Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct ChunkOffsetMap {
	chunkmap: BTreeMap<u64, u64>, //<chunk no, offset in segment>
	target_size: usize,
}

impl Default for ChunkOffsetMap {
	fn default() -> Self {
		Self::new_empty()
	}
}

impl ChunkMap for ChunkOffsetMap {
	type Value = u64;

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
		let enc_buffer = Encryption::decrypt_chunk_offset_map(key, structure_data, chunk_no, encryption_algorithm.borrow())?;
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
		let enc_buffer = Encryption::encrypt_chunk_offset_map(key, vec, chunk_no, encryption_algorithm.borrow())?;
		Ok(enc_buffer)
	}
}

impl HeaderCoding for ChunkOffsetMap {
	type Item = ChunkOffsetMap;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_CHUNK_OFFSET_MAP
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_CHUNK_OFFSET_MAP
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
impl fmt::Display for ChunkOffsetMap {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl ChunkOffsetMap {
	fn struct_name(&self) -> &'static str {
		"ChunkOffsetMap"
	}
}

#[cfg(feature = "serde")]
impl Serialize for ChunkOffsetMap {
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