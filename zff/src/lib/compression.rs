// - STD
use std::io::{Read};

// - internal
use crate::{
	Result,
};

// - external
use zstd;
use serde::{Serialize};

/// Defines all compression algorithms, which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Serialize)]
pub enum CompressionAlgorithm {
	/// No compression - encoded as 0 in the header.
	None = 0,
	/// Zstd compression (default) - encoded as 1 in the header.
	Zstd = 1,
}

/// The function gets a Reader, which implements [Read](https://doc.rust-lang.org/std/io/trait.Read.html) and returns a new Reader
/// which directly compresses the read data with the given [CompressionAlgorithm] and compression level.
/// # Example
/// use std::fs::File;
/// use std::io::{Read,Write};
/// use zff::{compression_stream,CompressionAlgorithm};
/// 
/// fn main() -> std::io::Result<()> {
/// 	let input_file = File::open("/etc/os-release")?;
/// 	let algorithm = CompressionAlgorithm::Zstd;
/// 	let stream = compression_stream(input_file, algorithm, 3).unwrap();
/// 	
/// 	let mut output_file = File::create("/tmp/compressed_etc_os-release.zst")?;
/// 	
/// 	let _ = output_file.write(&mut stream)?;
/// }
pub fn compression_stream<R>(input: R, algorithm: &CompressionAlgorithm, compression_level: &u8) -> Result<Box<dyn Read>>
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

/// The function gets a Reader, which implements [Read](https://doc.rust-lang.org/std/io/trait.Read.html) and returns a new Reader
/// which directly decompresses the read data with the given [CompressionAlgorithm].
/// # Example
/// use std::fs::File;
/// use std::io::{Read,Write};
/// use zff::{decompression_stream,CompressionAlgorithm};
/// 
/// fn main() -> std::io::Result<()> {
/// 	let input_file = File::open("/tmp/compressed_etc_os-release.zst")?;
/// 	let algorithm = CompressionAlgorithm::Zstd;
/// 	let stream = decompression_stream(input_file, algorithm).unwrap();
/// 	
/// 	let mut output_file = File::create("/tmp/decompressed_etc_os-release")?;
/// 	
/// 	let _ = output_file.write(&mut stream)?;
/// }
pub fn decompression_stream<R>(input: R, algorithm: CompressionAlgorithm) -> Result<Box<dyn Read>>
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