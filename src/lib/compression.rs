// - STD
use std::io::Read;
use std::borrow::Borrow;
use std::fmt;

// - internal
use crate::{
	Result,
};

// - external
#[cfg(feature = "serde")]
use serde::{
	Deserialize,
	Serialize,
};

/// Defines all compression algorithms, which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum CompressionAlgorithm {
	/// No compression - encoded as 0 in the header.
	None = 0,
	/// Zstd compression (default) - encoded as 1 in the header.
	Zstd = 1,
	/// LZ4 compression - encoded as 2 in the header. LZ4 frame format is used (not the LZ4 block format) for compression.
	Lz4 = 2,
}

impl From<&str> for CompressionAlgorithm {
	fn from(algorithm: &str) -> CompressionAlgorithm {
		let algorithm = algorithm.to_lowercase();
		match algorithm.as_str() {
			"zstd" => CompressionAlgorithm::Zstd,
			"lz4" => CompressionAlgorithm::Lz4,
			_ => CompressionAlgorithm::None,
		}
	}
}

impl fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    	let value = match self {
    		CompressionAlgorithm::Zstd => "Zstd",
    		CompressionAlgorithm::Lz4 => "Lz4",
    		CompressionAlgorithm::None => "None",
    	};
        write!(f, "{value}")
    }
}

/// Decompresses a buffer with the given [CompressionAlgorithm].
pub fn decompress_buffer<C>(buffer: &[u8], compression_algorithm: C) -> Result<Vec<u8>>
where
	C: Borrow<CompressionAlgorithm>,
{
	match compression_algorithm.borrow() {
    	CompressionAlgorithm::None => Ok(buffer.to_vec()),
    	CompressionAlgorithm::Zstd => {
    		let mut decompressed_buffer = Vec::new();
			let mut decoder = zstd::stream::read::Decoder::new(buffer)?;
			decoder.read_to_end(&mut decompressed_buffer)?;
			Ok(decompressed_buffer)
    	},
    	CompressionAlgorithm::Lz4 => {
    		let mut decompressed_buffer = Vec::new();
			let mut decompressor = lz4_flex::frame::FrameDecoder::new(buffer);
			decompressor.read_to_end(&mut decompressed_buffer)?;
			Ok(decompressed_buffer)
    	}
    }
}

/// Decompresses a reader with the given [CompressionAlgorithm].
pub fn decompress_reader<C, R>(input: &mut R, compression_algorithm: C) -> Result<Box<dyn Read + Send + '_>>
where
	C: Borrow<CompressionAlgorithm>,
	R: Read + std::marker::Send + 'static,
{
	match compression_algorithm.borrow() {
		CompressionAlgorithm::None => Ok(Box::new(input)),
		CompressionAlgorithm::Zstd => {
			let decoder = zstd::stream::read::Decoder::new(input)?;
			Ok(Box::new(decoder))
		},
		CompressionAlgorithm::Lz4 => {
			let decompressor = lz4_flex::frame::FrameDecoder::new(input);
			Ok(Box::new(decompressor))
		},
	}
}