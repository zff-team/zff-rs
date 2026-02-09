// - Parent
use super::*;

/// Header for the chunked data (typically stored in a chunk header map).
/// The Header doesn't contain a chunk number, because it is stored in a map with the chunk number as key.
#[derive(Debug,Clone, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ChunkHeader {
	/// The offset, where the chunked data can be found (inside the appriopriate segment file).
    pub offset: u64,
	/// The length of the chunked data.
    pub size: u64,
    /// The flags of the chunked data.
    pub flags: ChunkFlags,
    /// The integrity hash (currently xxhash) of the chunked data.
	#[cfg_attr(feature = "serde", serde(serialize_with = "crate::helper::as_hex"))]
    pub integrity_hash: u64,
}

impl ChunkHeader {
	/// returns a new compression header with the given values.
	pub fn new(offset: u64, size: u64, flags: ChunkFlags, integrity_hash: u64) -> Self {
		Self {
            offset,
            size,
            flags,
            integrity_hash,
        }
	}
}

impl HeaderCoding for ChunkHeader {
	type Item = Self;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_CHUNK_HEADER
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_CHUNK_HEADER
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![Self::version()];
		vec.append(&mut self.offset.encode_directly());
        vec.append(&mut self.size.encode_directly());
        vec.append(&mut self.flags.encode_directly());
        vec.append(&mut self.integrity_hash.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?;
		let offset = u64::decode_directly(&mut cursor)?;
		let size = u64::decode_directly(&mut cursor)?;
		let flags = ChunkFlags::decode_directly(&mut cursor)?;
		let integrity_hash = u64::decode_directly(&mut cursor)?;
		Ok(ChunkHeader::new(offset, size, flags, integrity_hash))
	}

	fn struct_name() -> &'static str {
		"ChunkHeader"
	}
}

// - implement fmt::Display
impl fmt::Display for ChunkHeader {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", Self::struct_name())
	}
}

impl ValueEncoder for ChunkHeader {
    fn identifier(&self) -> u8 {
        METADATA_EXT_TYPE_IDENTIFIER_CHUNK_HEADER
    }

    fn encode_directly(&self) -> Vec<u8> {
        HeaderCoding::encode_directly(self)
    }
}

impl ValueDecoder for ChunkHeader {
    type Item = ChunkHeader;

    fn decode_directly<R: Read>(data: &mut R) -> Result<Self::Item> {
        <ChunkHeader as HeaderCoding>::decode_directly(data)
    }
}

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
		write!(f, "{}", Self::struct_name())
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

	fn struct_name() -> &'static str {
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