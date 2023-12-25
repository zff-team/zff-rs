// - STD
use std::io::Cursor;
use std::fmt;

use crate::constants::DEFAULT_HEADER_VERSION_COMPRESSION_HEADER;
// - internal
use crate::{
	Result,
	ZffError,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	CompressionAlgorithm,
};

use crate::{
	HEADER_IDENTIFIER_COMPRESSION_HEADER,
	ERROR_HEADER_DECODER_COMPRESSION_ALGORITHM,
};

// - external
#[cfg(feature = "serde")]
use serde::{
	Deserialize,
	Serialize,
};

/// Header for the data compression parameters.\
/// This header is part of the main header.
#[derive(Debug,Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct CompressionHeader {
	/// The compression algorithm. The appropriate algorithms/values
	/// could be found at [CompressionAlgorithm](enum.CompressionAlgorithm.html).
	pub algorithm: CompressionAlgorithm,
	/// The compression level.
	pub level: u8,
	/// The compression threshold.
	pub threshold: f32,
}

impl CompressionHeader {
	/// returns a new compression header with the given values.
	pub fn new(compression_algo: CompressionAlgorithm, level: u8, threshold: f32) -> CompressionHeader {
		Self {
			algorithm: compression_algo,
			level,
			threshold,
		}
	}
}

impl HeaderCoding for CompressionHeader {
	type Item = CompressionHeader;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_COMPRESSION_HEADER
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_COMPRESSION_HEADER
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![Self::version(), self.algorithm.clone() as u8, self.level];
		vec.append(&mut self.threshold.encode_directly());
		
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<CompressionHeader> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?;
		let algorithm = match u8::decode_directly(&mut cursor) {
			Ok(0) => CompressionAlgorithm::None,
			Ok(1) => CompressionAlgorithm::Zstd,
			Ok(2) => CompressionAlgorithm::Lz4,
			_ => return Err(ZffError::new_header_decode_error(ERROR_HEADER_DECODER_COMPRESSION_ALGORITHM))
		};
		let level = u8::decode_directly(&mut cursor)?;
		let threshold = f32::decode_directly(&mut cursor)?;
		Ok(CompressionHeader::new(algorithm, level, threshold))
	}
}

// - implement fmt::Display
impl fmt::Display for CompressionHeader {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl CompressionHeader {
	fn struct_name(&self) -> &'static str {
		"CompressionHeader"
	}
}