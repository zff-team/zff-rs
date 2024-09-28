// - STD
use core::borrow::Borrow;
use std::path::Path;
use std::cmp::PartialEq;
use std::collections::{HashMap, BTreeMap};
use std::io::{Cursor, Read};
use std::fmt;

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	ZffError,
	HEADER_IDENTIFIER_CHUNK_OFFSET_MAP,
	DEFAULT_HEADER_VERSION_CHUNK_OFFSET_MAP,
	HEADER_IDENTIFIER_CHUNK_SIZE_MAP,
	DEFAULT_HEADER_VERSION_CHUNK_SIZE_MAP,
	HEADER_IDENTIFIER_CHUNK_FLAG_MAP,
	DEFAULT_HEADER_VERSION_CHUNK_FLAG_MAP,
	HEADER_IDENTIFIER_CHUNK_CRC_MAP,
	DEFAULT_HEADER_VERSION_CHUNK_CRC_MAP,
	HEADER_IDENTIFIER_CHUNK_SAMEBYTES_MAP,
	DEFAULT_HEADER_VERSION_CHUNK_SAMEBYTES_MAP,
	HEADER_IDENTIFIER_CHUNK_DEDUPLICATION_MAP,
	DEFAULT_HEADER_VERSION_CHUNK_DEDUPLICATION_MAP,
	CHUNK_MAP_TABLE,
	ERROR_FLAG_VALUE,
	COMPRESSION_FLAG_VALUE,
	SAME_BYTES_FLAG_VALUE,
	DUPLICATION_FLAG_VALUE,
	ENCRYPTION_FLAG_VALUE,
	EMPTY_FILE_FLAG_VALUE,
	VIRTUAL_FLAG_VALUE,
	METADATA_EXT_TYPE_IDENTIFIER_U8,
};

#[cfg(feature = "serde")]
use crate::helper::string_to_str;

// - external
use redb::Database;
use blake3::Hash as Blake3Hash;
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

/// The appropriate Chunkmap type.
pub enum ChunkMapType {
	/// The offset map.
	OffsetMap,
	/// The size map.
	SizeMap,
	/// The flags map.
	FlagsMap,
	/// The CRC map.
	CRCMap,
	/// The sambebytes map.
	SamebytesMap,
	/// The deduplication map.
	DeduplicationMap,
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
	pub flags_map: ChunkFlagMap,
	/// The CRC map.
	pub crc_map: ChunkCRCMap,
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
		self.crc_map.chunkmap().is_empty() && 
		self.same_bytes_map.chunkmap().is_empty() && 
		self.duplicate_chunks.chunkmap().is_empty()
	}
}


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

impl ChunkOffsetMap {
	/// returns a new [ChunkOffsetMap] with the given values.
	pub fn with_data(chunkmap: BTreeMap<u64, u64>) -> Self {
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

	/// Returns a reference to the inner map
	pub fn chunkmap(&self) -> &BTreeMap<u64, u64> {
		&self.chunkmap
	}

	/// The encoded size of this map.
	pub fn current_size(&self) -> usize {
		self.chunkmap.len() * 16 + 8
	}

	/// Reset the target size to the given value.
	pub fn set_target_size(&mut self, target_size: usize) {
		self.target_size = target_size
	}

	/// Tries to add a chunk entry.  
	/// Returns true, if the chunk no / offset pair was added to the map.  
	/// Returns false, if the map is full (in this case, the pair was **not** added to the map).
	pub fn add_chunk_entry(&mut self, chunk_no: u64, offset: u64) -> bool {
		if self.is_full() { //24 -> 8bytes for next chunk_no, 8bytes for next offset, 8 bytes for the size of the encoded BTreeMap
			false
		} else {
			self.chunkmap.entry(chunk_no).or_insert(offset);
			true
		}
	}

	/// Checks if the map is full (returns true if, returns false if not).
	pub fn is_full(&self) -> bool {
		if self.target_size < self.current_size() + 24 { //24 -> 8bytes for next chunk_no, 8bytes for next offset, 8 bytes for the size of the encoded BTreeMap
			true
		} else {
			false
		}
	}

	/// Returns the inner map and replaces it with an empty map.
	pub fn flush(&mut self) -> BTreeMap<u64, u64> {
		std::mem::take(&mut self.chunkmap)
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

/// The ChunkSizeMap stores the chunk size of the appropriate chunk.
#[derive(Debug,Clone,PartialEq,Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct ChunkSizeMap {
	chunkmap: BTreeMap<u64, u64>, //<chunk no, chunk size in segment>
	target_size: usize,
}

impl Default for ChunkSizeMap {
	fn default() -> Self {
		Self::new_empty()
	}
}

impl ChunkSizeMap {
	/// returns a new [ChunkOffSizeMap] with the given values.
	pub fn with_data(chunkmap: BTreeMap<u64, u64>) -> Self {
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

	/// Returns a reference to the inner map
	pub fn chunkmap(&self) -> &BTreeMap<u64, u64> {
		&self.chunkmap
	}

	/// The encoded size of this map.
	pub fn current_size(&self) -> usize {
		self.chunkmap.len() * 16 + 8
	}

	/// Reset the target size to the given value.
	pub fn set_target_size(&mut self, target_size: usize) {
		self.target_size = target_size
	}

	/// Tries to add a chunk entry.  
	/// Returns true, if the chunk no / chunk size pair was added to the map.  
	/// Returns false, if the map is full (in this case, the pair was **not** added to the map).
	pub fn add_chunk_entry(&mut self, chunk_no: u64, chunk_size: u64) -> bool {
		if self.is_full() { //24 -> 8bytes for next chunk_no, 8bytes for next offset, 8 bytes for the size of the encoded BTreeMap
			false
		} else {
			self.chunkmap.entry(chunk_no).or_insert(chunk_size);
			true
		}
	}

	/// Checks if the map is full (returns true if, returns false if not).
	pub fn is_full(&self) -> bool {
		if self.target_size < self.current_size() + 24 { //24 -> 8bytes for next chunk_no, 8bytes for next chunk size, 8 bytes for the size of the encoded BTreeMap
			true
		} else {
			false
		}
	}

	/// Returns the inner map and replaces it with an empty map.
	pub fn flush(&mut self) -> BTreeMap<u64, u64> {
		std::mem::take(&mut self.chunkmap)
	}
}

impl HeaderCoding for ChunkSizeMap {
	type Item = ChunkSizeMap;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_CHUNK_SIZE_MAP
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_CHUNK_SIZE_MAP
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
impl fmt::Display for ChunkSizeMap {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl ChunkSizeMap {
	fn struct_name(&self) -> &'static str {
		"ChunkSizeMap"
	}
}

#[cfg(feature = "serde")]
impl Serialize for ChunkSizeMap {
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


/// The Chunkmap stores the information where the each appropriate chunk could be found.
#[derive(Debug,Clone,PartialEq,Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct ChunkFlagMap {
	chunkmap: BTreeMap<u64, ChunkFlags>, //<chunk no, ChunkFlags>
	target_size: usize,
}

impl Default for ChunkFlagMap {
	fn default() -> Self {
		Self::new_empty()
	}
}

impl ChunkFlagMap {
	/// returns a new [ChunkFlagMap] with the given values.
	pub fn with_data(chunkmap: BTreeMap<u64, ChunkFlags>) -> Self {
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

	/// Returns a reference to the inner map
	pub fn chunkmap(&self) -> &BTreeMap<u64, ChunkFlags> {
		&self.chunkmap
	}

	/// The encoded size of this map.
	pub fn current_size(&self) -> usize {
		self.chunkmap.len() * 9 + 8
	}

	/// Reset the target size to the given value.
	pub fn set_target_size(&mut self, target_size: usize) {
		self.target_size = target_size
	}

	/// Tries to add a chunk entry.  
	/// Returns true, if the chunk no / ChunkFlags pair was added to the map.  
	/// Returns false, if the map is full (in this case, the pair was **not** added to the map).
	pub fn add_chunk_entry(&mut self, chunk_no: u64, flag: &ChunkFlags) -> bool {
		if self.is_full() { //24 -> 8bytes for next chunk_no, 8bytes for next offset, 8 bytes for the size of the encoded BTreeMap
			false
		} else {
			self.chunkmap.entry(chunk_no).or_insert(flag.clone());
			true
		}
	}

	/// Checks if the map is full (returns true if, returns false if not).
	pub fn is_full(&self) -> bool {
		if self.target_size < self.current_size() + 17 { //17 -> 8bytes for next chunk_no, 1 byte for flag, 8 bytes for the size of the encoded BTreeMap
			true
		} else {
			false
		}
	}

	/// Returns the inner map and replaces it with an empty map.
	pub fn flush(&mut self) -> BTreeMap<u64, ChunkFlags> {
		std::mem::take(&mut self.chunkmap)
	}
}

impl HeaderCoding for ChunkFlagMap {
	type Item = ChunkFlagMap;

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
impl fmt::Display for ChunkFlagMap {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl ChunkFlagMap {
	fn struct_name(&self) -> &'static str {
		"ChunkFlagMap"
	}
}

#[cfg(feature = "serde")]
impl Serialize for ChunkFlagMap {
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

/// The Chunkmap stores the information where the each appropriate chunk could be found.
#[derive(Debug,Clone,PartialEq,Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct ChunkCRCMap {
	chunkmap: BTreeMap<u64, CRC32Value>, //<chunk no, offset in segment>
	target_size: usize,
}

impl Default for ChunkCRCMap {
	fn default() -> Self {
		Self::new_empty()
	}
}

impl ChunkCRCMap {
	/// returns a new [ChunkCRCMap] with the given values.
	pub fn with_data(chunkmap: BTreeMap<u64, CRC32Value>) -> Self {
		Self {
			chunkmap,
			target_size: 0,
		}
	}

	/// Returns a reference to the inner map
	pub fn chunkmap(&self) -> &BTreeMap<u64, CRC32Value> {
		&self.chunkmap
	}

	/// The encoded size of this map.
	pub fn current_size(&self) -> usize {
		match self.chunkmap.first_key_value() {
			Some(entry) => {
				let value_size = match entry.1 {
					CRC32Value::Unencrypted(_) => 4,
					CRC32Value::Encrypted(value) => value.len(),
				};
				self.chunkmap.len() * (8 + value_size) + 8
			}
			None => return 0,
		}
	}

	/// returns a new, empty [ChunkMap] with the given values.
	pub fn new_empty() -> Self {
		Self {
			chunkmap: BTreeMap::new(),
			target_size: 0,
		}
	}

	/// Reset the target size to the given value.
	pub fn set_target_size(&mut self, target_size: usize) {
		self.target_size = target_size
	}

	/// Tries to add a chunk entry.  
	/// Returns true, if the chunk no / crc value pair was added to the map.  
	/// Returns false, if the map is full (in this case, the pair was **not** added to the map).
	pub fn add_chunk_entry(&mut self, chunk_no: u64, crc: &CRC32Value) -> bool {
		if self.is_full() { //24 -> 8bytes for next chunk_no, 8bytes for next offset, 8 bytes for the size of the encoded BTreeMap
			false
		} else {
			self.chunkmap.entry(chunk_no).or_insert(crc.clone());
			true
		}
	}

	/// Checks if the map is full (returns true if, returns false if not).
	pub fn is_full(&self) -> bool {
		if self.target_size < self.current_size() + 20 { //20 -> 8bytes for next chunk_no, 4 bytes for crc, 8 bytes for the size of the encoded BTreeMap
			true
		} else {
			false
		}
	}

	/// Returns the inner map and replaces it with an empty map.
	pub fn flush(&mut self) -> BTreeMap<u64, CRC32Value> {
		std::mem::take(&mut self.chunkmap)
	}
}

impl HeaderCoding for ChunkCRCMap {
	type Item = ChunkCRCMap;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_CHUNK_CRC_MAP
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_CHUNK_CRC_MAP
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
		let chunkmap = BTreeMap::<u64, CRC32Value>::decode_directly(&mut cursor)?;
		Ok(Self::with_data(chunkmap))
	}
}

// - implement fmt::Display
impl fmt::Display for ChunkCRCMap {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl ChunkCRCMap {
	fn struct_name(&self) -> &'static str {
		"ChunkCRCMap"
	}
}

#[cfg(feature = "serde")]
impl Serialize for ChunkCRCMap {
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

impl ChunkSamebytesMap {
	/// returns a new [ChunkSamebytesMap] with the given values.
	pub fn with_data(chunkmap: BTreeMap<u64, u8>) -> Self {
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

	/// Returns a reference to the inner map
	pub fn chunkmap(&self) -> &BTreeMap<u64, u8> {
		&self.chunkmap
	}

	/// The encoded size of this map.
	pub fn current_size(&self) -> usize {
		self.chunkmap.len() * 9 + 8
	}

	/// Reset the target size to the given value.
	pub fn set_target_size(&mut self, target_size: usize) {
		self.target_size = target_size
	}

	/// Tries to add a chunk entry.  
	/// Returns true, if the chunk no / chunk size pair was added to the map.  
	/// Returns false, if the map is full (in this case, the pair was **not** added to the map).
	pub fn add_chunk_entry(&mut self, chunk_no: u64, samebyte: u8) -> bool {
		if self.is_full() { //24 -> 8bytes for next chunk_no, 8bytes for next offset, 8 bytes for the size of the encoded BTreeMap
			false
		} else {
			self.chunkmap.entry(chunk_no).or_insert(samebyte);
			true
		}
	}

	/// Checks if the map is full (returns true if, returns false if not).
	pub fn is_full(&self) -> bool {
		if self.target_size < self.current_size() + 17 { //24 -> 8bytes for next chunk_no, 1 byte for the samebyte, 8 bytes for the size of the encoded BTreeMap
			true
		} else {
			false
		}
	}

	/// Returns the inner map and replaces it with an empty map.
	pub fn flush(&mut self) -> BTreeMap<u64, u8> {
		std::mem::take(&mut self.chunkmap)
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

impl ChunkDeduplicationMap {
	/// returns a new [ChunkDeduplicationMap] with the given values.
	pub fn with_data(chunkmap: BTreeMap<u64, u64>) -> Self {
		Self {
			chunkmap,
			target_size: 0,
		}
	}

	/// returns a new, empty [ChunkDeduplicationMap] with the given values.
	pub fn new_empty() -> Self {
		Self {
			chunkmap: BTreeMap::new(),
			target_size: 0,
		}
	}

	/// Returns a reference to the inner map
	pub fn chunkmap(&self) -> &BTreeMap<u64, u64> {
		&self.chunkmap
	}

	/// The encoded size of this map.
	pub fn current_size(&self) -> usize {
		self.chunkmap.len() * 16 + 8
	}

	/// Reset the target size to the given value.
	pub fn set_target_size(&mut self, target_size: usize) {
		self.target_size = target_size
	}

	/// Tries to add a chunk entry.  
	/// Returns true, if the chunk no / chunk size pair was added to the map.  
	/// Returns false, if the map is full (in this case, the pair was **not** added to the map).
	pub fn add_chunk_entry(&mut self, chunk_no: u64, dedup_chunk_no: u64) -> bool {
		if self.is_full() { //24 -> 8bytes for next chunk_no, 8bytes for next offset, 8 bytes for the size of the encoded BTreeMap
			false
		} else {
			self.chunkmap.entry(chunk_no).or_insert(dedup_chunk_no);
			true
		}
	}

	/// Checks if the map is full (returns true if, returns false if not).
	pub fn is_full(&self) -> bool {
		if self.target_size < self.current_size() + 24 { //24 -> 8bytes for next chunk_no, 8 bytes for the dedup chunk no, 8 bytes for the size of the encoded BTreeMap
			true
		} else {
			false
		}
	}

	/// Returns the inner map and replaces it with an empty map.
	pub fn flush(&mut self) -> BTreeMap<u64, u64> {
		std::mem::take(&mut self.chunkmap)
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
}

// - implement fmt::Display
impl fmt::Display for ChunkDeduplicationMap {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl ChunkDeduplicationMap {
	fn struct_name(&self) -> &'static str {
		"ChunkDeduplicationMap"
	}
}

#[cfg(feature = "serde")]
impl Serialize for ChunkDeduplicationMap {
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
        let mut state = serializer.serialize_struct(self.struct_name(), 6)?;
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
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl DeduplicationChunkMap {
	fn struct_name(&self) -> &'static str {
		"DeduplicationChunkMap"
	}
}