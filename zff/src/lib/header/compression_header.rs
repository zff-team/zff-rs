// - STD
use std::io::{Cursor};

// - internal
use crate::{
	Result,
	ZffError,
	HeaderCoding,
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
/// This header is part of the main header.
#[derive(Debug,Clone,Serialize)]
pub struct CompressionHeader {
	version: u8,
	algorithm: CompressionAlgorithm,
	level: u8
}

impl CompressionHeader {
	/// returns a new compression header with the given values.
	pub fn new(version: u8,compression_algo: CompressionAlgorithm, level: u8) -> CompressionHeader {
		Self {
			version: version,
			algorithm: compression_algo,
			level: level,
		}
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

impl HeaderCoding for CompressionHeader {
	type Item = CompressionHeader;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_COMPRESSION_HEADER
	}

	fn version(&self) -> u8 {
		self.version
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.push(self.version);
		vec.push(self.algorithm.clone() as u8);
		vec.push(self.level);
		
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<CompressionHeader> {
		let mut cursor = Cursor::new(data);
		let version = u8::decode_directly(&mut cursor)?;
		let algorithm = match u8::decode_directly(&mut cursor) {
			Ok(0) => CompressionAlgorithm::None,
			Ok(1) => CompressionAlgorithm::Zstd,
			Ok(2) => CompressionAlgorithm::Lz4,
			_ => return Err(ZffError::new_header_decode_error(ERROR_HEADER_DECODER_COMPRESSION_ALGORITHM))
		};
		let level = u8::decode_directly(&mut cursor)?;
		Ok(CompressionHeader::new(version, algorithm, level))
	}
}