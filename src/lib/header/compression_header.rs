// - STD
use std::fmt;
use std::io::{Cursor};

// - internal
use crate::prelude::*;

// - external
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};


/// Header for the data compression parameters.\
/// This header is part of the main header.
///
/// # Example
/// ```
/// use zff::{header::CompressionHeader, CompressionAlgorithm};
///
/// // Create a compression header with Zstd compression, level 3, and default threshold
/// let compression_header = CompressionHeader::new(
///     CompressionAlgorithm::Zstd,
///     3,
///     1.05
/// );
///
/// // Create a compression header with no compression
/// let no_compression_header = CompressionHeader::new(
///     CompressionAlgorithm::None,
///     0,
///     1.0
/// );
/// ```
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
	///
	/// # Example
	/// ```
	/// use zff::{header::CompressionHeader, CompressionAlgorithm};
	///
	/// // Create a header for Zstd compression at level 6
	/// let header = CompressionHeader::new(CompressionAlgorithm::Zstd, 6, 1.05);
	/// assert!(matches!(header.algorithm, CompressionAlgorithm::Zstd));
	/// assert_eq!(header.level, 6);
	/// ```
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

	fn encode_content(&self) -> Vec<u8> {
		let mut vec = vec![self.algorithm.clone() as u8, self.level];
		vec.extend_from_slice(&self.threshold.encode_directly());
		vec
	}

	fn decode_content(data: &[u8]) -> Result<CompressionHeader> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?;
		let algorithm = match u8::decode_directly(&mut cursor) {
			Ok(0) => CompressionAlgorithm::None,
			Ok(1) => CompressionAlgorithm::Zstd,
			Ok(2) => CompressionAlgorithm::Lz4,
			_ => return Err(ZffError::new(ZffErrorKind::Invalid, ERROR_HEADER_DECODER_COMPRESSION_ALGORITHM))
		};
		let level = u8::decode_directly(&mut cursor)?;
		let threshold = f32::decode_directly(&mut cursor)?;
		Ok(CompressionHeader::new(algorithm, level, threshold))
	}
}

// - implement fmt::Display
impl fmt::Display for CompressionHeader {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", Self::struct_name())
	}
}