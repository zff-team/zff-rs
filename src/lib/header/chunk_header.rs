// - STD
use std::io::{Cursor,Read};

// - external
use ed25519_dalek::{SIGNATURE_LENGTH};

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	HEADER_IDENTIFIER_CHUNK_HEADER,
	ERROR_FLAG_VALUE,
	COMPRESSION_FLAG_VALUE,
	SAME_BYTES_FLAG_VALUE,
	DUPLICATION_FLAG_VALUE,
	ENCRYPTION_FLAG_VALUE,
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

/// Header for chunk data.\
/// Each data chunk has his own chunk header. After the header, the chunked data follows.
#[derive(Debug,Clone)]
pub struct ChunkHeader {
	pub version: u8,
	pub chunk_number: u64,
	pub chunk_size: u64,
	pub flags: ChunkHeaderFlags,
	pub crc32: u32,
	pub ed25519_signature: Option<[u8; SIGNATURE_LENGTH]>,
}

impl ChunkHeader {
	/// creates a new empty chunk header with a given chunk number. All other values are set to ```0``` or ```None```.
	pub fn new_empty(version: u8, chunk_number: u64) -> ChunkHeader {
		Self {
			version,
			chunk_number,
			chunk_size: 0,
			flags: ChunkHeaderFlags::default(),
			crc32: 0,
			ed25519_signature: None,
		}
	}

	/// creates a new header from the given data.
	pub fn new(version: u8, chunk_number: u64, chunk_size: u64, flags:ChunkHeaderFlags, crc32: u32, ed25519_signature: Option<[u8; SIGNATURE_LENGTH]>) -> ChunkHeader {
		Self {
			version,
			chunk_number,
			chunk_size,
			flags,
			crc32,
			ed25519_signature
		}
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
		match self.ed25519_signature {
			None => (),
			Some(signature) => vec.append(&mut signature.encode_directly()),
		};
		
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<ChunkHeader> {
		let mut cursor = Cursor::new(&data);
		let version = u8::decode_directly(&mut cursor)?;
		let chunk_number = u64::decode_directly(&mut cursor)?;
		let chunk_size = u64::decode_directly(&mut cursor)?;
		let flags = ChunkHeaderFlags::from(u8::decode_directly(&mut cursor)?);
		let crc32 = u32::decode_directly(&mut cursor)?;
		let mut ed25519_signature = None;
		if cursor.position() < (data.len() as u64 - 1) {
			let mut buffer = [0; SIGNATURE_LENGTH];
			cursor.read_exact(&mut buffer)?;
			ed25519_signature = Some(buffer);
		}

		Ok(ChunkHeader::new(version, chunk_number, chunk_size, flags, crc32, ed25519_signature))
	}
}

/// Header for chunk data (contains encrypted crc32 and ed25519 signature).
#[derive(Debug,Clone)]
pub struct EncryptedChunkHeader {
	pub version: u8,
	pub chunk_number: u64,
	pub chunk_size: u64,
	pub flags: ChunkHeaderFlags,
	pub crc32: u32,
	pub ed25519_signature: Option<[u8; SIGNATURE_LENGTH]>,
}

impl EncryptedChunkHeader {
	/// creates a new empty chunk header with a given chunk number. All other values are set to ```0``` or ```None```.
	pub fn new_empty(version: u8, chunk_number: u64) -> EncryptedChunkHeader {
		Self {
			version,
			chunk_number,
			chunk_size: 0,
			flags: ChunkHeaderFlags::default(),
			crc32: 0,
			ed25519_signature: None,
		}
	}

	/// creates a new header from the given data.
	pub fn new(version: u8, 
		chunk_number: u64, 
		chunk_size: u64, 
		flags:ChunkHeaderFlags, 
		crc32: u32, 
		ed25519_signature: Option<[u8; SIGNATURE_LENGTH]>) -> EncryptedChunkHeader {
		Self {
			version,
			chunk_number,
			chunk_size,
			flags,
			crc32,
			ed25519_signature
		}
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
		match self.ed25519_signature {
			None => (),
			Some(signature) => vec.append(&mut signature.encode_directly()),
		};
		
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<EncryptedChunkHeader> {
		let mut cursor = Cursor::new(&data);
		let version = u8::decode_directly(&mut cursor)?;
		let chunk_number = u64::decode_directly(&mut cursor)?;
		let chunk_size = u64::decode_directly(&mut cursor)?;
		let flags = ChunkHeaderFlags::from(u8::decode_directly(&mut cursor)?);
		let crc32 = u32::decode_directly(&mut cursor)?;
		let mut ed25519_signature = None;
		if cursor.position() < (data.len() as u64 - 1) {
			let mut buffer = [0; SIGNATURE_LENGTH];
			cursor.read_exact(&mut buffer)?;
			ed25519_signature = Some(buffer);
		}

		Ok(EncryptedChunkHeader::new(version, chunk_number, chunk_size, flags, crc32, ed25519_signature))
	}
}