// - STD
use std::io::Read;

// - internal
use crate::{
	Result,
	CompressionAlgorithm,
};

// - external
use zstd;

pub fn compress_filestream<R>(input: R, algorithm: CompressionAlgorithm, compression_level: u8) -> Result<Box<dyn Read>>
where
	R: Read + 'static,
{
	match algorithm {
		CompressionAlgorithm::None => {
			return Ok(Box::new(input))
		}
		CompressionAlgorithm::Zstd => {
			let encoder = zstd::stream::read::Encoder::new(input, compression_level.into())?;
			return Ok(Box::new(encoder));
		},
	}
}

pub fn decompress_filestream<R>(input: R, algorithm: CompressionAlgorithm) -> Result<Box<dyn Read>>
where
	R: Read + 'static
{
	match algorithm {
		CompressionAlgorithm::None => {
			return Ok(Box::new(input))
		}
		CompressionAlgorithm::Zstd => {
			let decoder = zstd::stream::read::Decoder::new(input)?;
			return Ok(Box::new(decoder));
		}
	}
}