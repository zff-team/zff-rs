// - STD
use std::io::{Read,Write};

// - internal
use crate::{
	Result,
	CompressionAlgorithm,
};

// - external
use zstd;

pub fn compress_filestream<R>(input: R, algorithm: &CompressionAlgorithm, compression_level: &u8) -> Result<Box<dyn Read>>
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

pub fn write_from_compressed_filestream<R, W>(
	input: &mut R,
	output: &mut W,
	split_size: usize,
	buffersize: usize) -> Result<u64>
where
	R: Read + 'static,
	W: Write,
{
	let mut buffer = vec![0; buffersize];
	let mut written_bytes: usize = 0;
	loop {
		let mut bytes_read = 0;
		while bytes_read < buffersize {
			let r = input.read(&mut buffer[bytes_read..])?;
			if r == 0 {
				break;
			}
			bytes_read += r;
		}
		if bytes_read == 0 {
			break;
		};
		output.write_all(&buffer)?;
		written_bytes += bytes_read;
		if bytes_read != buffersize {
			break;
		}
		if written_bytes >= split_size {
			break;
		}
	}
	Ok(written_bytes as u64)
}