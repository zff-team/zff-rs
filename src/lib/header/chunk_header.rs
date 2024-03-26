// - STD
use std::borrow::Borrow;
use std::io::Cursor;
use std::fmt;

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	encryption::{Encryption, EncryptionAlgorithm},
	HEADER_IDENTIFIER_CHUNK_HEADER,
	ERROR_FLAG_VALUE,
	COMPRESSION_FLAG_VALUE,
	SAME_BYTES_FLAG_VALUE,
	DUPLICATION_FLAG_VALUE,
	ENCRYPTION_FLAG_VALUE,
	EMPTY_FILE_FLAG_VALUE,
	VIRTUAL_FLAG_VALUE,
	DEFAULT_HEADER_VERSION_CHUNK_HEADER
};

// - external
#[cfg(feature = "serde")]
use serde::{
	Deserialize,
	Serialize,
};

/// The appropriate flags for each chunk.
#[derive(Debug,Clone,Default)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ChunkHeaderFlags {
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

impl From<u8> for ChunkHeaderFlags {
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
impl fmt::Display for ChunkHeaderFlags {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl ChunkHeaderFlags {
	fn struct_name(&self) -> &'static str {
		"ChunkHeaderFlags"
	}
}

/// Header for chunk data.  
/// Each data chunk has his own chunk header. After the header, the chunked data follows.
#[derive(Debug,Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ChunkHeader {
	/// the appropriate chunk number.
	pub chunk_number: u64,
	/// the appropriate size of the chunk data (in the final optionally compressed and encrypted form).
	pub chunk_size: u64,
	/// the appropriate chunk header flags.
	pub flags: ChunkHeaderFlags,
	/// the crc32 value to ensure (a bit) integrity.
	pub crc32: u32,
}

impl ChunkHeader {
	/// creates a new empty chunk header with a given chunk number. All other values are set to ```0``` or ```None```.
	pub fn new_empty(chunk_number: u64) -> ChunkHeader {
		Self {
			chunk_number,
			chunk_size: 0,
			flags: ChunkHeaderFlags::default(),
			crc32: 0,
		}
	}

	/// creates a new header from the given data.
	pub fn new(
		chunk_number: u64,
		chunk_size: u64,
		flags:ChunkHeaderFlags,
		crc32: u32) -> ChunkHeader {
		Self {
			chunk_number,
			chunk_size,
			flags,
			crc32,
		}
	}

	/// Tries to encrypt the ChunkHeader. If an error occures, the unencrypted ChunkHeader is still available.
	pub fn encrypt<A, K>(&self, key: K, algorithm: A) -> Result<EncryptedChunkHeader>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		let crc32 = Encryption::encrypt_chunk_header_crc32(&key, self.crc32.to_le_bytes(), self.chunk_number, algorithm.borrow())?;
		let mut flags = self.flags.clone();
		flags.encryption = true;
		Ok(EncryptedChunkHeader::new(self.chunk_number, self.chunk_size, flags, crc32))
	}

	/// Tries to encrypt the ChunkHeader. Consumes theunencrypted ChunkHeader, regardless of whether an error occurs or not.
	pub fn encrypt_and_consume<A, K>(self, key: K, algorithm: A) -> Result<EncryptedChunkHeader>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		self.encrypt(key, algorithm)
	}
}

impl HeaderCoding for ChunkHeader {
	type Item = ChunkHeader;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_CHUNK_HEADER
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_CHUNK_HEADER
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![Self::version()];

		vec.append(&mut self.chunk_number.encode_directly());
		vec.append(&mut self.chunk_size.encode_directly());
		let mut flags: u8 = 0;
		if self.flags.error {
			flags += ERROR_FLAG_VALUE;
		};
		if self.flags.compression {
			flags += COMPRESSION_FLAG_VALUE;
		};
		if self.flags.same_bytes {
			flags += SAME_BYTES_FLAG_VALUE;
		}
		if self.flags.duplicate {
			flags += DUPLICATION_FLAG_VALUE;
		}
		if self.flags.encryption {
			flags += ENCRYPTION_FLAG_VALUE;
		}
		if self.flags.empty_file {
			flags += EMPTY_FILE_FLAG_VALUE;
		}
		if self.flags.virtual_chunk {
			flags += VIRTUAL_FLAG_VALUE;
		}
		vec.append(&mut flags.encode_directly());
		vec.append(&mut self.crc32.encode_directly());
		
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<ChunkHeader> {
		let mut cursor = Cursor::new(&data);
		Self::check_version(&mut cursor)?;
		let chunk_number = u64::decode_directly(&mut cursor)?;
		let chunk_size = u64::decode_directly(&mut cursor)?;
		let flags = ChunkHeaderFlags::from(u8::decode_directly(&mut cursor)?);
		let crc32 = u32::decode_directly(&mut cursor)?;

		Ok(ChunkHeader::new(chunk_number, chunk_size, flags, crc32))
	}
}

// - implement fmt::Display
impl fmt::Display for ChunkHeader {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl ChunkHeader {
	fn struct_name(&self) -> &'static str {
		"ChunkHeader"
	}
}

/// Header for (encrypted) chunk data (contains encrypted crc32 and ed25519 signature).
#[derive(Debug,Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct EncryptedChunkHeader {
	/// the appropriate chunk number
	pub chunk_number: u64,
	/// the appropriate size of the chunk data (in the final optionally compressed and encrypted form).
	pub chunk_size: u64,
	/// the appropriate chunk header flags.
	pub flags: ChunkHeaderFlags,
	/// the encrypted crc32 value.
	#[cfg_attr(feature = "serde", serde(serialize_with = "crate::helper::buffer_to_hex", deserialize_with = "crate::helper::hex_to_buffer"))]
	pub crc32: Vec<u8>,
}

impl EncryptedChunkHeader {
	/// creates a new empty chunk header with a given chunk number. All other values are set to ```0``` or ```None```.
	pub fn new_empty(chunk_number: u64) -> EncryptedChunkHeader {
		Self {
			chunk_number,
			chunk_size: 0,
			flags: ChunkHeaderFlags::default(),
			crc32: Vec::new(),
		}
	}

	/// creates a new header from the given data.
	pub fn new(
		chunk_number: u64, 
		chunk_size: u64, 
		flags:ChunkHeaderFlags, 
		crc32: Vec<u8>) -> EncryptedChunkHeader {
		Self {
			chunk_number,
			chunk_size,
			flags,
			crc32,
		}
	}

	/// tries to decrypt the ChunkHeader. If an error occures, the EncryptedChunkHeader is still available.
	pub fn decrypt<A, K>(&self, key: K, algorithm: A) -> Result<ChunkHeader>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		let crc32: u32 = Encryption::decrypt_chunk_header_crc32(&key, &self.crc32, self.chunk_number, algorithm.borrow())?;
		Ok(ChunkHeader::new(self.chunk_number, self.chunk_size, self.flags.clone(), crc32))
	}

	/// tries to decrypt the ChunkHeader. Consumes the EncryptedChunkHeader, regardless of whether an error occurs or not.
	pub fn decrypt_and_consume<A, K>(self, key: K, algorithm: A) -> Result<ChunkHeader>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		let crc32: u32 = Encryption::decrypt_chunk_header_crc32(&key, &self.crc32, self.chunk_number, algorithm.borrow())?;
		Ok(ChunkHeader::new(self.chunk_number, self.chunk_size, self.flags, crc32))
	}
}

impl HeaderCoding for EncryptedChunkHeader {
	type Item = EncryptedChunkHeader;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_CHUNK_HEADER
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_CHUNK_HEADER
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![Self::version()];

		vec.append(&mut self.chunk_number.encode_directly());
		vec.append(&mut self.chunk_size.encode_directly());
		let mut flags: u8 = 0;
		if self.flags.error {
			flags += ERROR_FLAG_VALUE;
		};
		if self.flags.compression {
			flags += COMPRESSION_FLAG_VALUE;
		};
		if self.flags.same_bytes {
			flags += SAME_BYTES_FLAG_VALUE;
		}
		if self.flags.duplicate {
			flags += DUPLICATION_FLAG_VALUE;
		}
		if self.flags.encryption {
			flags += ENCRYPTION_FLAG_VALUE;
		}
		if self.flags.empty_file {
			flags += EMPTY_FILE_FLAG_VALUE;
		}
		if self.flags.virtual_chunk {
			flags += VIRTUAL_FLAG_VALUE;
		}
		vec.append(&mut flags.encode_directly());
		vec.append(&mut self.crc32.encode_directly());
		
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<EncryptedChunkHeader> {
		let mut cursor = Cursor::new(&data);
		Self::check_version(&mut cursor)?;
		let chunk_number = u64::decode_directly(&mut cursor)?;
		let chunk_size = u64::decode_directly(&mut cursor)?;
		let flags = ChunkHeaderFlags::from(u8::decode_directly(&mut cursor)?);
		let crc32 = Vec::<u8>::decode_directly(&mut cursor)?;

		Ok(EncryptedChunkHeader::new(chunk_number, chunk_size, flags, crc32))
	}
}

// - implement fmt::Display
impl fmt::Display for EncryptedChunkHeader {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl EncryptedChunkHeader {
	fn struct_name(&self) -> &'static str {
		"EncryptedChunkHeader"
	}
}