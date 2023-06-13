// - STD
use std::borrow::Borrow;
use std::io::{Cursor};

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	ZffError,
	ZffErrorKind,
	encryption::{Encryption, EncryptionAlgorithm},
	HEADER_IDENTIFIER_CHUNK_HEADER,
	ERROR_FLAG_VALUE,
	COMPRESSION_FLAG_VALUE,
	SAME_BYTES_FLAG_VALUE,
	DUPLICATION_FLAG_VALUE,
	ENCRYPTION_FLAG_VALUE,
	DEFAULT_HEADER_VERSION_CHUNK_HEADER
};

#[derive(Debug,Clone,Default)]
pub struct ChunkHeaderFlags {
	pub error: bool,
	pub compression: bool,
	pub same_bytes: bool,
	pub duplicate: bool,
	pub encryption: bool,
}

impl From<u8> for ChunkHeaderFlags {
	fn from(flag_values: u8) -> Self {
		Self {
			error: flag_values & ERROR_FLAG_VALUE != 0,
			compression: flag_values & COMPRESSION_FLAG_VALUE != 0,
			same_bytes: flag_values & SAME_BYTES_FLAG_VALUE != 0,
			duplicate: flag_values & DUPLICATION_FLAG_VALUE != 0,
			encryption: flag_values & ENCRYPTION_FLAG_VALUE != 0,
		}
	}
}

/// Header for chunk data.  
/// Each data chunk has his own chunk header. After the header, the chunked data follows.
#[derive(Debug,Clone)]
pub struct ChunkHeader {
	pub version: u8,
	pub chunk_number: u64,
	pub chunk_size: u64,
	pub flags: ChunkHeaderFlags,
	pub crc32: u32,
}

impl ChunkHeader {
	/// creates a new empty chunk header with a given chunk number. All other values are set to ```0``` or ```None```.
	pub fn new_empty(chunk_number: u64) -> ChunkHeader {
		Self {
			version: DEFAULT_HEADER_VERSION_CHUNK_HEADER,
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
			version: DEFAULT_HEADER_VERSION_CHUNK_HEADER,
			chunk_number,
			chunk_size,
			flags,
			crc32,
		}
	}

	/// tries to encrypt the ChunkHeader. If an error occures, the unencrypted ChunkHeader is still available.
	pub fn encrypt<A, K>(&self, key: K, algorithm: A) -> Result<EncryptedChunkHeader>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		let crc32 = Encryption::encrypt_chunk_header_crc32(&key, self.crc32.to_le_bytes(), self.chunk_number, algorithm.borrow())?;
		Ok(EncryptedChunkHeader::new(self.chunk_number, self.chunk_size, self.flags.clone(), crc32))
	}

	/// tries to encrypt the ChunkHeader. Consumes theunencrypted ChunkHeader, regardless of whether an error occurs or not.
	pub fn encrypt_and_consume<A, K>(self, key: K, algorithm: A) -> Result<EncryptedChunkHeader>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		let crc32 = Encryption::encrypt_chunk_header_crc32(&key, self.crc32.to_le_bytes(), self.chunk_number, algorithm.borrow())?;
		Ok(EncryptedChunkHeader::new(self.chunk_number, self.chunk_size, self.flags, crc32))
	}
}

impl HeaderCoding for ChunkHeader {
	type Item = ChunkHeader;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_CHUNK_HEADER
	}

	fn version(&self) -> u8 {
		self.version
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![self.version];

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
		vec.append(&mut flags.encode_directly());
		vec.append(&mut self.crc32.encode_directly());
		
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<ChunkHeader> {
		let mut cursor = Cursor::new(&data);
		// check if version correspondends to the current version
		match u8::decode_directly(&mut cursor)? {
			DEFAULT_HEADER_VERSION_CHUNK_HEADER => (),
			other_version => return Err(ZffError::new(ZffErrorKind::UnsupportedVersion, other_version.to_string())),
		};
		let chunk_number = u64::decode_directly(&mut cursor)?;
		let chunk_size = u64::decode_directly(&mut cursor)?;
		let flags = ChunkHeaderFlags::from(u8::decode_directly(&mut cursor)?);
		let crc32 = u32::decode_directly(&mut cursor)?;

		Ok(ChunkHeader::new(chunk_number, chunk_size, flags, crc32))
	}
}

/// Header for chunk data (contains encrypted crc32 and ed25519 signature).
#[derive(Debug,Clone)]
pub struct EncryptedChunkHeader {
	pub version: u8,
	pub chunk_number: u64,
	pub chunk_size: u64,
	pub flags: ChunkHeaderFlags,
	pub crc32: Vec<u8>,
}

impl EncryptedChunkHeader {
	/// creates a new empty chunk header with a given chunk number. All other values are set to ```0``` or ```None```.
	pub fn new_empty(chunk_number: u64) -> EncryptedChunkHeader {
		Self {
			version: DEFAULT_HEADER_VERSION_CHUNK_HEADER,
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
			version: DEFAULT_HEADER_VERSION_CHUNK_HEADER,
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

	fn version(&self) -> u8 {
		self.version
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![self.version];

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
		vec.append(&mut flags.encode_directly());
		vec.append(&mut self.crc32.encode_directly());
		
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<EncryptedChunkHeader> {
		let mut cursor = Cursor::new(&data);
		// check if version correspondends to the current version
		match u8::decode_directly(&mut cursor)? {
			DEFAULT_HEADER_VERSION_CHUNK_HEADER => (),
			other_version => return Err(ZffError::new(ZffErrorKind::UnsupportedVersion, other_version.to_string())),
		};
		let chunk_number = u64::decode_directly(&mut cursor)?;
		let chunk_size = u64::decode_directly(&mut cursor)?;
		let flags = ChunkHeaderFlags::from(u8::decode_directly(&mut cursor)?);
		let crc32 = Vec::<u8>::decode_directly(&mut cursor)?;

		Ok(EncryptedChunkHeader::new(chunk_number, chunk_size, flags, crc32))
	}
}