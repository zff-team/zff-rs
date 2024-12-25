// - parent
use super::*;

// - internal
use crate::{
    HEADER_IDENTIFIER_CHUNK_FLAG_MAP,
	DEFAULT_HEADER_VERSION_CHUNK_FLAG_MAP,
	ERROR_FLAG_VALUE,
	COMPRESSION_FLAG_VALUE,
	SAME_BYTES_FLAG_VALUE,
	DUPLICATION_FLAG_VALUE,
	ENCRYPTION_FLAG_VALUE,
	EMPTY_FILE_FLAG_VALUE,
	VIRTUAL_FLAG_VALUE,
	METADATA_EXT_TYPE_IDENTIFIER_U8,
};

/// The appropriate flags for each chunk.
#[derive(Debug,Clone,Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ChunkFlags {
	/// is set, if an read error is occured and the data in this chunk could be corrupted.
	pub error: bool,
	/// is set, if the data in the chunk are compressed.
	pub compression: bool,
	/// is set, if the chunk contains the same bytes.
	pub same_bytes: bool,
	/// is set, if this chunk is a duplicate of an other chunk.
	pub duplicate: bool,
	/// is set, if the chunk data is encrypted.
	pub encryption: bool,
	/// is set, if this is a placeholder chunk of an empty file.
	pub empty_file: bool,
	/// is set, if the chunk is a virtual chunk.
	pub virtual_chunk: bool,
}

impl From<u8> for ChunkFlags {
	fn from(flag_values: u8) -> Self {
		Self {
			error: flag_values & ERROR_FLAG_VALUE != 0,
			compression: flag_values & COMPRESSION_FLAG_VALUE != 0,
			same_bytes: flag_values & SAME_BYTES_FLAG_VALUE != 0,
			duplicate: flag_values & DUPLICATION_FLAG_VALUE != 0,
			encryption: flag_values & ENCRYPTION_FLAG_VALUE != 0,
			empty_file: flag_values & EMPTY_FILE_FLAG_VALUE != 0,
			virtual_chunk: flag_values & VIRTUAL_FLAG_VALUE != 0,
		}
	}
}

// - implement fmt::Display
impl fmt::Display for ChunkFlags {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl ChunkFlags {
	/// Creates an emtpy [ChunkFlags] struct with all flags set to false.
	pub fn new() -> Self {
		Self::default()
	}

	/// Returns the byte representation of the flags.
	pub fn as_bytes(&self) -> u8 {
		let mut flag_value: u8 = 0;
		if self.error { flag_value |= ERROR_FLAG_VALUE; }
		if self.compression { flag_value |= COMPRESSION_FLAG_VALUE; }
		if self.same_bytes { flag_value |= SAME_BYTES_FLAG_VALUE; }
		if self.duplicate { flag_value |= DUPLICATION_FLAG_VALUE; }
		if self.encryption { flag_value |= ENCRYPTION_FLAG_VALUE; }
		if self.empty_file { flag_value |= EMPTY_FILE_FLAG_VALUE; }
		if self.virtual_chunk { flag_value |= VIRTUAL_FLAG_VALUE; }
		flag_value
	}

	fn struct_name(&self) -> &'static str {
		"ChunkHeaderFlags"
	}
}

impl ValueEncoder for ChunkFlags {
	fn encode_directly(&self) -> Vec<u8> {
		let mut flag_value: u8 = 0;
		if self.error { flag_value |= ERROR_FLAG_VALUE; }
		if self.compression { flag_value |= COMPRESSION_FLAG_VALUE; }
		if self.same_bytes { flag_value |= SAME_BYTES_FLAG_VALUE; }
		if self.duplicate { flag_value |= DUPLICATION_FLAG_VALUE; }
		if self.encryption { flag_value |= ENCRYPTION_FLAG_VALUE; }
		if self.empty_file { flag_value |= EMPTY_FILE_FLAG_VALUE; }
		if self.virtual_chunk { flag_value |= VIRTUAL_FLAG_VALUE; }
		flag_value.encode_directly()
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_U8
	}
}

impl ValueDecoder for ChunkFlags {
	type Item = Self;
	
	fn decode_directly<R: Read>(data: &mut R) -> Result<Self> {
		let flag_value = u8::decode_directly(data)?;
		Ok(ChunkFlags::from(flag_value))
	}
}


/// The Chunkmap stores the information where the each appropriate chunk could be found.
#[derive(Debug,Clone,PartialEq,Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct ChunkFlagsMap {
	chunkmap: BTreeMap<u64, ChunkFlags>, //<chunk no, ChunkFlags>
	target_size: usize,
}

impl Default for ChunkFlagsMap {
	fn default() -> Self {
		Self::new_empty()
	}
}

impl ChunkMap for ChunkFlagsMap {
	type Value = ChunkFlags;

	/// returns a new [ChunkFlagsMap] with the given values.
	fn with_data(chunkmap: BTreeMap<u64, Self::Value>) -> Self {
		Self {
			chunkmap,
			target_size: 0,
		}
	}

	/// returns a new, empty [ChunkFlagsMap] with the given values.
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
			Some(_) => self.chunkmap.len() * (8 + 1) + 8, //8 -> 8bytes for the chunk no, 1 byte for the chunk flags
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
			self.chunkmap.entry(chunk_no).or_insert(value.borrow().clone());
			true
		}
	}

	fn is_full(&self) -> bool {
		if self.target_size < self.current_size() + 17 { //24 -> 8bytes for next chunk_no, 1 byte for the chunk flags, 8 bytes for the size of the encoded BTreeMap
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
		let enc_buffer = ChunkFlagsMap::decrypt(key, structure_data, chunk_no, encryption_algorithm.borrow())?;
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

impl HeaderCoding for ChunkFlagsMap {
	type Item = ChunkFlagsMap;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_CHUNK_FLAG_MAP
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_CHUNK_FLAG_MAP
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
		let chunkmap = BTreeMap::<u64, ChunkFlags>::decode_directly(&mut cursor)?;
		Ok(Self::with_data(chunkmap))
	}
}

// - implement fmt::Display
impl fmt::Display for ChunkFlagsMap {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl ChunkFlagsMap {
	fn struct_name(&self) -> &'static str {
		"ChunkFlagMap"
	}
}

impl Encryption for ChunkFlagsMap {
	fn crypto_nonce_padding() -> u8 {
		0b00000111
	}
}

#[cfg(feature = "serde")]
impl Serialize for ChunkFlagsMap {
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