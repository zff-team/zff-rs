// - STD
use std::io::{Cursor,Read};

// - external
use ed25519_dalek::{SIGNATURE_LENGTH};

// - internal
use crate::{
	Result,
	HeaderEncoder,
	HeaderDecoder,
	ValueEncoder,
	ValueDecoder,
	HeaderObject,
	HEADER_IDENTIFIER_CHUNK_HEADER,
	CHUNK_HEADER_CONTENT_LEN_WITHOUT_SIGNATURE,
};

/// Header for chunk data.\
/// Each chunk has his own chunk header. A chunk header has the following layout:
/// 
/// | Magic bytes | Header length | header version | chunk number | chunk size | crc32   | ed25519 signature<br>\<OPTIONAL\> |
/// |-------------|---------------|----------------|--------------|------------|---------|-----------------------------------|
/// | 4 bytes     | 8 bytes       | 1 byte         | 8 bytes      | 8 bytes    | 4 bytes | 64 bytes                          |
/// | 0x7A666643  | uint64        | uint8          | uint64       | uint64     | uint32  | \<BYTES\>                         |
/// after the header, the chunked data follows.
#[derive(Debug,Clone)]
pub struct ChunkHeader {
	header_version: u8,
	chunk_number: u64,
	chunk_size: u64,
	crc32: u32,
	ed25519_signature: Option<[u8; SIGNATURE_LENGTH]>,
}

impl ChunkHeader {
	/// creates a new header from the given data.
	pub fn new(header_version: u8, chunk_number: u64, chunk_size: u64, crc32: u32, ed25519_signature: Option<[u8; SIGNATURE_LENGTH]>) -> ChunkHeader {
		Self {
			header_version: header_version,
			chunk_number: chunk_number,
			chunk_size: chunk_size,
			crc32: crc32,
			ed25519_signature: ed25519_signature
		}
	}

	/// overwrites the chunk size in the header with the given value. This can be useful, if you create an 'empty'
	/// header (with size=0) and want to set the size after reading the data from source to buffer.
	pub fn set_chunk_size(&mut self, size: u64) {
		self.chunk_size = size
	}

	/// returns the size of the appropriate chunk
	pub fn chunk_size(&self) -> &u64 {
		&self.chunk_size
	}

	/// overwrites the crc32 value in the header with the given value. This can be useful, if you create an 'empty'
	/// header (with crc32=0) and want to set the crc32 value after reading the data from source to buffer.
	pub fn set_crc32(&mut self, crc32: u32) {
		self.crc32 = crc32
	}

	/// overwrites the signature in the header with the given value. This can be useful, if you create an 'empty'
	/// header (with signature=None) and want to set the signature after reading the data from source to buffer.
	/// Note: The Ed25519 signature per chunk is **optional**, so you have to set the signature as an ```Option<[u8; 64]>```.
	pub fn set_signature(&mut self, signature: Option<[u8; SIGNATURE_LENGTH]>) {
		self.ed25519_signature = signature
	}

	/// sets the chunk number to the next number. This can be useful, for example,
	/// if you clone a chunk header from the previous one or something like that.
	pub fn next_number(&mut self) {
		self.chunk_number += 1;
	}

	/// returns the chunk number of the chunk (header).
	pub fn chunk_number(&self) -> u64 {
		self.chunk_number
	}
}

impl HeaderObject for ChunkHeader {
	fn identifier() -> u32 {
		HEADER_IDENTIFIER_CHUNK_HEADER
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.push(self.header_version);
		vec.append(&mut self.chunk_number.encode_directly());
		vec.append(&mut self.chunk_size.encode_directly());
		vec.append(&mut self.crc32.encode_directly());
		match self.ed25519_signature {
			None => (),
			Some(signature) => vec.append(&mut signature.encode_directly()),
		};
		
		vec
	}
}

impl HeaderEncoder for ChunkHeader {}

impl HeaderDecoder for ChunkHeader {
	type Item = ChunkHeader;

	fn decode_content(data: Vec<u8>) -> Result<ChunkHeader> {
		let data_len = data.len();
		let mut cursor = Cursor::new(data);
		let header_version = u8::decode_directly(&mut cursor)?;
		let chunk_number = u64::decode_directly(&mut cursor)?;
		let chunk_size = u64::decode_directly(&mut cursor)?;
		let crc32 = u32::decode_directly(&mut cursor)?;
		let mut ed25519_signature = None;
		if data_len > (CHUNK_HEADER_CONTENT_LEN_WITHOUT_SIGNATURE) {
			let mut buffer = [0; SIGNATURE_LENGTH];
			cursor.read_exact(&mut buffer)?;
			ed25519_signature = Some(buffer);
		}

		Ok(ChunkHeader::new(header_version, chunk_number, chunk_size, crc32, ed25519_signature))
	}
}