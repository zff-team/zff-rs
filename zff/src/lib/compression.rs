// - STD
use std::io::{Read,Write};

// - internal
use crate::{
	Result,
	CompressionAlgorithm,
};

// - external
use zstd;

pub fn to_compression_stream<R>(input: R, algorithm: &CompressionAlgorithm, compression_level: &u8) -> Result<Box<dyn Read>>
where
	R: Read + 'static,
{
	match algorithm {
		CompressionAlgorithm::None => {
			return Ok(Box::new(input))
		}
		CompressionAlgorithm::Zstd => {
			let encoder = zstd::stream::read::Encoder::new(input, *compression_level as i32)?;
			return Ok(Box::new(encoder));
		},
	}
}

pub fn to_decompression_stream<R>(input: R, algorithm: CompressionAlgorithm) -> Result<Box<dyn Read>>
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

pub fn to_compression_writer<W>(output: W, algorithm: CompressionAlgorithm, compression_level: &u8) -> Result<Box<dyn Write>>
where
	W: Write + 'static
{
	match algorithm {
		CompressionAlgorithm::None => {
			return Ok(Box::new(output))
		},
		CompressionAlgorithm::Zstd => {
			let encoder = zstd::stream::write::Encoder::new(output, *compression_level as i32)?.auto_finish();
			return Ok(Box::new(encoder))
		}
	}
}