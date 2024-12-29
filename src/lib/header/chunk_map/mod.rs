// - STD
use core::borrow::Borrow;
use std::path::Path;
use std::cmp::PartialEq;
use std::collections::{HashMap, BTreeMap};
use std::io::{Cursor, Read};
use std::fmt;

// - modules
mod chunk_flags;
mod chunk_offset;
mod chunk_size;
mod chunk_xxhash;
mod chunk_same_bytes;
mod chunk_deduplication;

// - use
pub use chunk_flags::*;
pub use chunk_offset::*;
pub use chunk_size::*;
pub use chunk_xxhash::*;
pub use chunk_same_bytes::*;
pub use chunk_deduplication::*;

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	ZffError,
    ZffErrorKind,
    EncryptionAlgorithm,
    Encryption,
    DEFAULT_LENGTH_HEADER_IDENTIFIER,
    DEFAULT_LENGTH_VALUE_HEADER_LENGTH,
    ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER,
};

#[cfg(feature = "serde")]
use crate::helper::string_to_str;

// - external
#[cfg(feature = "serde")]
use serde::{
	Deserialize,
	Serialize,
	ser::{Serializer, SerializeStruct},
};
#[cfg(feature = "serde")]
use hex;
#[cfg(feature = "serde")]
use redb::ReadableTable;

#[repr(C)]
#[derive(Debug)]
/// The appropriate Chunkmap type.
pub enum ChunkMapType {
	/// The offset map.
	OffsetMap = 0,
	/// The size map.
	SizeMap = 1,
	/// The flags map.
	FlagsMap = 2,
	/// The xxhash map.
	XxHashMap = 3,
	/// The sambebytes map.
	SamebytesMap = 4,
	/// The deduplication map.
	DeduplicationMap = 5,
}

impl fmt::Display for ChunkMapType {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    	let value = match self {
    		ChunkMapType::OffsetMap => "OffsetMap",
			ChunkMapType::SizeMap => "SizeMap",
			ChunkMapType::FlagsMap => "FlagsMap",
			ChunkMapType::XxHashMap => "XxHashMap",
			ChunkMapType::SamebytesMap => "SamebytesMap",
			ChunkMapType::DeduplicationMap => "DeduplicationMap",
    	};
        write!(f, "{value}")
    }
}

/// The ChunkMaps struct contains all chunk maps.
#[derive(Debug,Clone,PartialEq,Eq,Default)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct ChunkMaps {
	/// The offset map.
	pub offset_map: ChunkOffsetMap,
	/// The size map.
	pub size_map: ChunkSizeMap,
	/// The flags map.
	pub flags_map: ChunkFlagsMap,
	/// The xxhash map.
	pub xxhash_map: ChunkXxHashMap,
	/// The same bytes map.
	pub same_bytes_map: ChunkSamebytesMap,
	/// The deduplication map.
	pub duplicate_chunks: ChunkDeduplicationMap,
}

impl ChunkMaps {
	/// checks if all maps are empty.
	pub fn is_empty(&self) -> bool {
		self.offset_map.chunkmap().is_empty() && 
		self.size_map.chunkmap().is_empty() && 
		self.flags_map.chunkmap().is_empty() && 
		self.xxhash_map.chunkmap().is_empty() && 
		self.same_bytes_map.chunkmap().is_empty() && 
		self.duplicate_chunks.chunkmap().is_empty()
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
	fn with_data(chunkmap: BTreeMap<u64, Self::Value>) -> Self;

	/// returns a new, empty chunk map with the given values.
	fn new_empty() -> Self;

    /// Returns the inner map and replaces it with an empty map.
	fn flush(&mut self) -> BTreeMap<u64, Self::Value>;

    /// Tries to add a chunk entry.  
	/// Returns true, if the chunk no / value pair was added to the map.  
	/// Returns false, if the map is full (in this case, the pair was **not** added to the map).
	fn add_chunk_entry<V: Borrow<Self::Value>>(&mut self, chunk_no: u64, value: V) -> bool;

    /// Checks if the map is full (returns true if, returns false if not).
	fn is_full(&self) -> bool;

    /// The encoded size of this map.
	fn current_size(&self) -> usize;

    /// Reset the target size to the given value.
	fn set_target_size(&mut self, target_size: usize);

    /// Returns a reference to the inner map
	fn chunkmap(&self) -> &BTreeMap<u64, Self::Value>;

    /// Returns the apprpropriate (encrypted) structure data
    fn inner_structure_data<D: Read>(data: &mut D) -> Result<Vec<u8>>
    where 
         Self: HeaderCoding,
    {
        if !Self::check_identifier(data) {
			return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER));
		}
		let header_length = Self::decode_header_length(data)? as usize;
		let version = u8::decode_directly(data)?;
		if version != Self::version() {
			return Err(ZffError::new(ZffErrorKind::UnsupportedVersion, version.to_string()));
		}
		let mut structure_content = vec![0u8; header_length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH-1];
		data.read_exact(&mut structure_content)?;
        Ok(structure_content)
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