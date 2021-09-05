// - STD
use std::collections::HashMap;
use std::io::{Read,Write};

// - internal
use crate::{
	Result,
	ChunkHeader,
	CompressionAlgorithm,
	HeaderEncoder,
	ZffError,
	ZffErrorKind,
	Encryption,
	EncryptionAlgorithm,
	HashType,
};

// - external
use digest::DynDigest;

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

fn read_chunk<R, H>(
	input: &mut R,
	chunk_size: usize,
	algorithm: &CompressionAlgorithm,
	compression_level: &u8,
	hasher_map: &mut HashMap<HashType, Box<H>>) -> Result<Vec<u8>>
where
    R: Read,
    H: DynDigest + ?Sized
{
    let buf = buffer_chunk(input, chunk_size)?;
    if buf.len() == 0 {
    	return Err(ZffError::new(ZffErrorKind::ReadEOF, ""));
    };
    for (_, hasher) in hasher_map {
    	hasher.update(&buf);
    }

    match algorithm {
    	CompressionAlgorithm::None => return Ok(buf),
    	CompressionAlgorithm::Zstd => {
    		let mut stream = zstd::stream::read::Encoder::new(buf.as_slice(), *compression_level as i32)?;
    		let buf = buffer_chunk(&mut stream, chunk_size*4)?;
    		Ok(buf)
    	}
    }
}


fn write_unencrypted_chunk<R, W, H>(
	input: &mut R,
	output: &mut W,
	chunk_size: usize,
	chunk_header: &mut ChunkHeader,
	compression_algorithm: &CompressionAlgorithm,
	compression_level: &u8,
	hasher_map: &mut HashMap<HashType, Box<H>>) -> Result<u64>
where
	R: Read,
	W: Write,
	H: DynDigest + ?Sized
{
	let compressed_chunk = read_chunk(input, chunk_size, compression_algorithm, compression_level, hasher_map)?;
	chunk_header.set_chunk_size(compressed_chunk.len() as u64);

	let mut written_bytes = 0;
	written_bytes += output.write(&chunk_header.encode_directly())?;
	written_bytes += output.write(&compressed_chunk)?;
	Ok(written_bytes as u64)
}

fn write_encrypted_chunk<R, W, H>(
	input: &mut R,
	output: &mut W,
	chunk_size: usize,
	chunk_header: &mut ChunkHeader,
	compression_algorithm: &CompressionAlgorithm,
	compression_level: &u8,
	encryption_key: &Vec<u8>,
	encryption_algorithm: &EncryptionAlgorithm,
	hasher_map: &mut HashMap<HashType, Box<H>>) -> Result<u64>
where
	R: Read,
	W: Write,
	H: DynDigest + ?Sized
{
	let compressed_chunk = read_chunk(input, chunk_size, compression_algorithm, compression_level, hasher_map)?;
	let encrypted_data = Encryption::encrypt_message(
		encryption_key,
		&compressed_chunk,
		chunk_header.chunk_number(),
		&encryption_algorithm)?;
	chunk_header.set_chunk_size(encrypted_data.len() as u64);

	let mut written_bytes = 0;
	written_bytes += output.write(&chunk_header.encode_directly())?;
	written_bytes += output.write(&encrypted_data)?;
	Ok(written_bytes as u64)
}

pub fn write_segment<R, W, H>(
	input: &mut R,
	output: &mut W,
	chunk_size: usize,
	chunk_header: &mut ChunkHeader,
	compression_algorithm: &CompressionAlgorithm,
	compression_level: &u8,
	segment_size: usize,
	encryption: &Option<(&Vec<u8>, EncryptionAlgorithm)>,
	hasher_map: &mut HashMap<HashType, Box<H>>) -> Result<u64>
where
	R: Read,
	W: Write,
	H: DynDigest + ?Sized
{
	let mut written_bytes: u64 = 0;
	loop {
		if (written_bytes + chunk_size as u64) > segment_size as u64 {
			return Ok(written_bytes);
		};
		chunk_header.next_number();
		match encryption {
			None => {
				let written_in_chunk = match write_unencrypted_chunk(
					input,
					output,
					chunk_size,
					chunk_header,
					compression_algorithm,
					compression_level,
					hasher_map) {
					Ok(data) => data,
					Err(e) => match e.get_kind() {
						ZffErrorKind::ReadEOF => return Ok(written_bytes),
						_ => return Err(e),
					},
				};
				written_bytes += written_in_chunk;
			},
			Some(ref encryption) => {
				let written_in_chunk = match write_encrypted_chunk(
					input,
					output,
					chunk_size,
					chunk_header,
					compression_algorithm,
					compression_level,
					&encryption.0,
					&encryption.1,
					hasher_map) {
					Ok(data) => data,
					Err(e) => match e.get_kind() {
						ZffErrorKind::ReadEOF => return Ok(written_bytes),
						_ => return Err(e),
					},
				};
				written_bytes += written_in_chunk;
			}
		}
	}
}