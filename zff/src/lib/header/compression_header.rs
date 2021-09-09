// - internal
use crate::{
	HeaderObject,
	HeaderEncoder,
	CompressionAlgorithm,
};

use crate::{
	HEADER_IDENTIFIER_COMPRESSION_HEADER,
};

/// Header for the data compression parameters.\
/// This header is part of the main header and has the following layout:
/// 
/// | Magic bytes | Header length | header version | algorithm | level  |
/// |-------------|---------------|----------------|-----------|--------|
/// | 4 bytes     | 8 bytes       | 1 byte         | 1 byte    | 1 byte |
/// | 0x7A666663  | uint64        | uint8          | uint8     | uint8  |
#[derive(Debug,Clone)]
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

impl HeaderEncoder for CompressionHeader {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_header = self.encode_header();
		let identifier = Self::identifier();
		let encoded_header_length = 4 + 8 + (encoded_header.len() as u64); //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.append(&mut encoded_header);

		vec
	}
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = Self::encode_key(key);
		vec.append(&mut encoded_key);
		vec.append(&mut self.encode_directly());
		vec
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