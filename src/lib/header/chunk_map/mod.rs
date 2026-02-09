// - Parent
use super::*;

// - modules
mod chunk_header;
mod chunk_same_bytes;
mod chunk_deduplication;

// - re-exports
pub use chunk_header::*;
pub use chunk_same_bytes::*;
pub use chunk_deduplication::*;

#[repr(C)]
#[derive(Debug)]
/// The appropriate Chunkmap type.
pub enum ChunkMapType {
	/// The header map.
	HeaderMap = 0,
	/// The sambebytes map.
	SamebytesMap = 1,
	/// The deduplication map.
	DeduplicationMap = 2,
}

impl fmt::Display for ChunkMapType {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    	let value = match self {
    		ChunkMapType::HeaderMap => "HeaderMap",
			ChunkMapType::SamebytesMap => "SamebytesMap",
			ChunkMapType::DeduplicationMap => "DeduplicationMap",
    	};
        write!(f, "{value}")
    }
}

/// The ChunkMaps struct contains all chunk maps.
#[derive(Debug,Clone,PartialEq,Eq, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct ChunkMaps {
	/// The offset map.
	pub header_map: ChunkHeaderMap,
	/// The same bytes map.
	pub same_bytes_map: ChunkSamebytesMap,
	/// The deduplication map.
	pub duplicate_chunks: ChunkDeduplicationMap,
}

impl ChunkMaps {
	/// Generates a new map
	pub fn new(header_map: ChunkHeaderMap, same_bytes_map: ChunkSamebytesMap, duplicate_chunks: ChunkDeduplicationMap) -> Self {
		Self {
			header_map,
			same_bytes_map,
			duplicate_chunks
		}
	}

	/// checks if all maps are empty.
	pub fn is_empty(&self) -> bool {
		self.header_map.chunkmap().is_empty() && 
		self.same_bytes_map.chunkmap().is_empty() && 
		self.duplicate_chunks.chunkmap().is_empty()
	}

	/// sets the appropriate object number
	pub fn set_object_number(&mut self, object_number: u64) {
		self.header_map.set_object_number(object_number);
		self.same_bytes_map.set_object_number(object_number);
		self.duplicate_chunks.set_object_number(object_number);
	}

}

#[cfg(feature = "serde")]
impl Serialize for ChunkMaps {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ChunkMaps", 6)?;
        if !self.header_map.is_empty() {
			state.serialize_field(string_to_str(self.header_map.to_string()), &self.header_map)?;
		}
		if !self.same_bytes_map.is_empty() {
			state.serialize_field(string_to_str(self.same_bytes_map.to_string()), &self.same_bytes_map)?;
		}
		if !self.duplicate_chunks.is_empty() {
			state.serialize_field(string_to_str(self.duplicate_chunks.to_string()), &self.duplicate_chunks)?;
		}
        state.end()
    }
}

/// The ChunkMap trait specifies common interface for various types of chunk maps.
///
/// The chunk maps are used to store information about chunks in the file.
/// The information is stored in the form of a map, where the key is the chunk offset
/// and the value is the chunk information.
///
/// The chunk maps are used to optimize the file reading.
pub trait ChunkMap {
     /// The type of the value stored in the map.
    type Value;

    /// returns a new chunk map with the given values.
	fn new(object_number: u64, chunkmap: BTreeMap<u64, Self::Value>) -> Self;

	/// returns a new, empty chunk map with the given values.
	fn new_empty(object_number: u64) -> Self;

    /// Returns the inner map and replaces it with an empty map.
	fn flush(&mut self) -> BTreeMap<u64, Self::Value>;

    /// Tries to add a chunk entry.  
	/// Returns true, if the chunk no / value pair was added to the map.  
	/// Returns false, if the map is full (in this case, the pair was **not** added to the map).
	fn add_chunk_entry(&mut self, chunk_no: u64, value: Self::Value) -> bool;

    /// Checks if the map is full (returns true if, returns false if not).
	fn is_full(&self) -> bool;

	/// Checks if the inner map is empty
	fn is_empty(&self) -> bool;

    /// The encoded size of this map.
	fn current_size(&self) -> usize;

    /// Reset the target size to the given value.
	fn set_target_size(&mut self, target_size: usize);

    /// Returns a reference to the inner map
	fn chunkmap(&self) -> &BTreeMap<u64, Self::Value>;

	/// Appends another chunkmap to this map
	fn append(&mut self, map: Self);

	/// Returns the corresponding object number of the inner map
	fn object_number(&self) -> u64;

	/// Sets the appropriate object number
	fn set_object_number(&mut self, object_number: u64);

    /// Returns the apprpropriate (encrypted) structure data
    fn inner_structure_data<D: Read>(data: &mut D) -> Result<ChunkMapInnerStructureData>
    where 
         Self: HeaderCoding,
    {
        if !Self::check_identifier(data) {
			return Err(ZffError::new(ZffErrorKind::Invalid, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER));
		}
		let header_length = Self::decode_header_length(data)? as usize;
		let version = u8::decode_directly(data)?;
		if version != Self::version() {
			return Err(ZffError::new(ZffErrorKind::Unsupported, format!("{ERROR_UNSUPPORTED_VERSION}{version}")));
		}
		let object_number = u64::decode_directly(data)?;
		let mut structure_content = vec![0u8; header_length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH-1];
		data.read_exact(&mut structure_content)?;
		Ok(ChunkMapInnerStructureData::new(object_number, structure_content))
    }

    /// Decrypts and decodes the chunk map by using the given key.
    fn decrypt_and_decode<K, A, D>(key: K, encryption_algorithm: A, data: &mut D, chunk_no: u64) -> Result<Self> 
    where
    K: AsRef<[u8]>, 
    A: Borrow<EncryptionAlgorithm>, 
    D: Read,
    Self: Sized + HeaderCoding;

	/// Encodes the inner map
	fn encode_map(&self) -> Vec<u8>;

	/// Encrypts the inner encoded map
	fn encrypt_encoded_map<K, A>(&self, key: K, encryption_algorithm: A, chunk_no: u64) -> Result<Vec<u8>>
    where
    K: AsRef<[u8]>,
    A: Borrow<EncryptionAlgorithm>,
    Self: HeaderCoding;

    /// Encodes and encrypts the appropriate chunk map
    fn encode_and_encrypt<K, A>(&self, key: K, encryption_algorithm: A, chunk_no: u64) -> Result<Vec<u8>>
    where
    K: AsRef<[u8]>,
    A: Borrow<EncryptionAlgorithm>,
    Self: HeaderCoding,
	{
		let mut vec = Vec::new();
		let mut encrypted_map = self.encrypt_encoded_map(key, encryption_algorithm, chunk_no)?;
		let identifier = Self::identifier();
		let encoded_header_length = (DEFAULT_LENGTH_HEADER_IDENTIFIER + DEFAULT_LENGTH_VALUE_HEADER_LENGTH + encrypted_map.len()) as u64; //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.append(&mut encrypted_map);

		Ok(vec)
	}
}


/// Structure data for chunk map inner structure.
/// This structure is used to store the structure data for chunk map inner structure.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChunkMapInnerStructureData {
	/// Object number for chunk map inner structure.
	pub object_number: u64,
	/// Structure data for chunk map inner structure.
	pub structure_data: Vec<u8>,
}

impl ChunkMapInnerStructureData {
	/// Creates a new chunk map inner structure data.
	pub fn new(object_number: u64, structure_data: Vec<u8>) -> Self {
		Self {
			object_number,
			structure_data,
		}
	}
}