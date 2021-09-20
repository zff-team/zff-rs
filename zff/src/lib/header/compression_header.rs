// - STD
use std::io::{Cursor};

// - internal
use crate::{
	Result,
	ZffError,
	HeaderObject,
	HeaderEncoder,
	HeaderDecoder,
	ValueDecoder,
	CompressionAlgorithm,
};

use crate::{
	HEADER_IDENTIFIER_COMPRESSION_HEADER,
	ERROR_HEADER_DECODER_COMPRESSION_ALGORITHM,
};

// - external
use serde::{Serialize};

/// Header for the data compression parameters.\
/// This header is part of the main header and has the following layout:
/// 
/// | Magic bytes | Header length | header version | algorithm | level  |
/// |-------------|---------------|----------------|-----------|--------|
/// | 4 bytes     | 8 bytes       | 1 byte         | 1 byte    | 1 byte |
/// | 0x7A666663  | uint64        | uint8          | uint8     | uint8  |
#[derive(Debug,Clone,Serialize)]
pub struct CompressionHeader {
	header_version: u8,
	algorithm: CompressionAlgorithm,
	level: u8
}

impl CompressionHeader {
	/// returns a new compression header with the given values.
	pub fn new(header_version: u8,compression_algo: CompressionAlgorithm, level: u8) -> CompressionHeader {
		Self {
			header_version: header_version,
			algorithm: compression_algo,
			level: level,
		}
	}

	/// returns the version of the header.
	pub fn header_version(&self) -> &u8 {
		&self.header_version
	}

	/// Returns the compression algorithm. The appropriate algorithms/values
	/// could be found at [CompressionAlgorithm](enum.CompressionAlgorithm.html).
	pub fn algorithm(&self) -> &CompressionAlgorithm {
		&self.algorithm
	}

	/// returns the compression level.
	pub fn level(&self) -> &u8 {
		&self.level
	}
}

impl HeaderObject for CompressionHeader {
	fn identifier() -> u32 {
		HEADER_IDENTIFIER_COMPRESSION_HEADER
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.push(self.header_version);
		vec.push(self.algorithm.clone() as u8);
		vec.push(self.level);
		
		vec
	}
}

impl HeaderEncoder for CompressionHeader {}

impl HeaderDecoder for CompressionHeader {
	type Item = CompressionHeader;

	fn decode_content(data: Vec<u8>) -> Result<CompressionHeader> {
		let mut cursor = Cursor::new(data);
		let header_version = u8::decode_directly(&mut cursor)?;
		let algorithm = match u8::decode_directly(&mut cursor) {
			Ok(0) => CompressionAlgorithm::None,
			Ok(1) => CompressionAlgorithm::Zstd,
			_ => return Err(ZffError::new_header_decode_error(ERROR_HEADER_DECODER_COMPRESSION_ALGORITHM))
		};
		let level = u8::decode_directly(&mut cursor)?;
		Ok(CompressionHeader::new(header_version, algorithm, level))
	}
}

impl From<&str> for CompressionAlgorithm {
	fn from(algorithm: &str) -> CompressionAlgorithm {
		let algorithm = algorithm.to_lowercase();
		match algorithm.as_str() {
			"zstd" => CompressionAlgorithm::Zstd,
			"none" | _ => CompressionAlgorithm::None,
		}
	}
}
