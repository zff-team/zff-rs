// - modules

// - STD
use std::io::{Read, copy as io_copy};

// - internal
use crate::{
    Result,
    ZffError,
    ZffErrorKind,
    CompressionAlgorithm,
    header::{CompressionHeader},
};

// - external
use crc32fast::{Hasher as CRC32Hasher};

// returns the buffer with the read bytes and the number of bytes which was read.
pub(crate) fn buffer_chunk<R>(
	input: &mut R,
	chunk_size: usize,
	) -> Result<(Vec<u8>, u64)> 
where
	R: Read
{
	let mut buf = vec![0u8; chunk_size];
    let mut bytes_read = 0;

    while bytes_read < chunk_size {
        let r = match input.read(&mut buf[bytes_read..]) {
        	Ok(r) => r,
        	Err(e) => match e.kind() {
        		std::io::ErrorKind::Interrupted => return Err(ZffError::new(ZffErrorKind::InterruptedInputStream, "")),
        		_ => return Err(ZffError::from(e)),
        	},
        };
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
    Ok((buf, bytes_read as u64))
}

/// calculates a crc32 hash for the given bytes.
pub fn calculate_crc32(buffer: &[u8]) -> u32 {
    let mut crc32_hasher = CRC32Hasher::new();
    crc32_hasher.update(buffer);
    
    crc32_hasher.finalize()
}

/// This function takes the buffered bytes and tries to compress them. If the compression rate is greater than the threshold value of the given
/// [CompressionHeader], the function returns a tuple of compressed bytes and the flag, if the bytes was compressed or not.
pub fn compress_buffer(buf: Vec<u8>, chunk_size: usize, compression_header: &CompressionHeader) -> Result<(Vec<u8>, bool)> {
    let mut compression_flag = false;
    let compression_threshold = compression_header.threshold();

    match compression_header.algorithm() {
        CompressionAlgorithm::None => Ok((buf, compression_flag)),
        CompressionAlgorithm::Zstd => {
            let compression_level = *compression_header.level() as i32;
            let mut stream = zstd::stream::read::Encoder::new(buf.as_slice(), compression_level)?;
            let (compressed_data, _) = buffer_chunk(&mut stream, chunk_size * *compression_header.level() as usize)?;
            if (buf.len() as f32 / compressed_data.len() as f32) < compression_threshold {
                Ok((buf, compression_flag))
            } else {
                compression_flag = true;
                Ok((compressed_data, compression_flag))
            }
        },
        CompressionAlgorithm::Lz4 => {
            let buffer = Vec::new();
            let mut compressor = lz4_flex::frame::FrameEncoder::new(buffer);
            io_copy(&mut buf.as_slice(), &mut compressor)?;
            let compressed_data = compressor.finish()?;
            if (buf.len() as f32 / compressed_data.len() as f32) < compression_threshold {
                Ok((buf, compression_flag))
            } else {
                compression_flag = true;
                Ok((compressed_data, compression_flag))
            }
        }
    }
}