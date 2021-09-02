// - STD
use std::io::{Read,Write};

// - internal
use crate::{
	Result,
	ChunkHeader,
	CompressionAlgorithm,
	HeaderEncoder,
	ZffError,
	ZffErrorKind,
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

pub fn compress_filestream_writer<W>(output: W, algorithm: CompressionAlgorithm, compression_level: &u8) -> Result<Box<dyn Write>>
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

fn buffer_chunk<R>(
	input: &mut R,
	chunk_size: usize,
	) -> Result<Vec<u8>>
where
	R: Read
{
	let mut buf = vec![0u8; chunk_size];
    let mut bytes_read = 0;

    while bytes_read < chunk_size {
        let r = input.read(&mut buf[bytes_read..])?;
        if r == 0 {
            break;
        }
        bytes_read += r;
    }

    let buf = if bytes_read == chunk_size {
        buf
    } else {
        buf[..bytes_read].to_vec()
    };
    return Ok(buf)
}

fn source_read_chunk<R>(
	input: &mut R,
	chunk_size: usize,
	algorithm: &CompressionAlgorithm,
	compression_level: &u8) -> Result<Vec<u8>>
where
    R: Read
{
    let buf = buffer_chunk(input, chunk_size)?;
    if buf.len() == 0 {
    	return Err(ZffError::new(ZffErrorKind::ReadEOF, ""));
    };

    match algorithm {
    	CompressionAlgorithm::None => return Ok(buf),
    	CompressionAlgorithm::Zstd => {
    		let mut stream = zstd::stream::read::Encoder::new(buf.as_slice(), *compression_level as i32)?;
    		let buf = buffer_chunk(&mut stream, chunk_size*4)?;
    		Ok(buf)
    	}
    }
}


fn write_unencrypted_chunk<R, W>(
	input: &mut R,
	output: &mut W,
	chunk_size: usize,
	mut chunk_header: ChunkHeader,
	compression_algorithm: &CompressionAlgorithm,
	compression_level: &u8) -> Result<u64>
where
	R: Read,
	W: Write
{
	let compressed_chunk = source_read_chunk(input, chunk_size, compression_algorithm, compression_level)?;
	chunk_header.set_chunk_size(compressed_chunk.len() as u64);

	let mut written_bytes = 0;
	written_bytes += output.write(&chunk_header.encode_directly())?;
	written_bytes += output.write(&compressed_chunk)?;
	Ok(written_bytes as u64)
}

pub fn write_segment<R, W>(
	input: &mut R,
	output: &mut W,
	chunk_size: usize,
	mut chunk_header: ChunkHeader,
	compression_algorithm: &CompressionAlgorithm,
	compression_level: &u8,
	split_size: usize) -> Result<u64>
where
	R: Read,
	W: Write
{
	let mut written_bytes: u64 = 0;
	loop {
		if (written_bytes + chunk_size as u64) > split_size as u64 {
			return Ok(written_bytes);
		};
		let chunk_header = chunk_header.next_header();
		let written_in_chunk = match write_unencrypted_chunk(
			input,
			output,
			chunk_size,
			chunk_header,
			compression_algorithm,
			compression_level) {
			Ok(data) => data,
			Err(e) => match e.get_kind() {
				ZffErrorKind::ReadEOF => return Ok(written_bytes),
				_ => return Err(e),
			},
		};
		written_bytes += written_in_chunk;
	}
}