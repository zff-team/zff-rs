// - STD
use std::collections::HashMap;
use std::io::{Read,Write,Seek,SeekFrom};

// - internal
use crate::{
	Result,
	header::{SegmentHeader,SegmentFooter,Segment,ChunkHeader},
	CompressionAlgorithm,
	HeaderEncoder,
	ZffError,
	ZffErrorKind,
	Encryption,
	EncryptionAlgorithm,
	HashType,
};

use crate::{
	DEFAULT_LENGTH_SEGMENT_FOOTER_EMPTY,
	DEFAULT_SEGMENT_FOOTER_VERSION,
};

// - external
use crc32fast::Hasher as CRC32Hasher;
use ed25519_dalek::{Keypair,Signer,SIGNATURE_LENGTH};
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

//TODO: optimization/code cleanup
fn prepare_chunk<R, H>(
	input: &mut R,
	chunk_size: usize,
	algorithm: &CompressionAlgorithm,
	compression_level: &u8,
	hasher_map: &mut HashMap<HashType, Box<H>>,
	signature_key: &Option<Keypair>) -> Result<(Vec<u8>, u32, Option<[u8; SIGNATURE_LENGTH]>)>
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
    let mut crc32_hasher = CRC32Hasher::new();
    crc32_hasher.update(&buf);
    let crc32 = crc32_hasher.finalize();

    let signature = match signature_key {
    	None => None,
    	Some(keypair) => Some(keypair.sign(&buf).to_bytes()),
    };

    match algorithm {
    	CompressionAlgorithm::None => return Ok((buf, crc32, signature)),
    	CompressionAlgorithm::Zstd => {
    		let mut stream = zstd::stream::read::Encoder::new(buf.as_slice(), *compression_level as i32)?;
    		let buf = buffer_chunk(&mut stream, chunk_size*4)?;
    		Ok((buf, crc32, signature))
    	}
    }
}

//TODO: optimization/code cleanup
fn write_unencrypted_chunk<R, W, H>(
	input: &mut R,
	output: &mut W,
	chunk_size: usize,
	chunk_header: &mut ChunkHeader,
	compression_algorithm: &CompressionAlgorithm,
	compression_level: &u8,
	hasher_map: &mut HashMap<HashType, Box<H>>,
	signature_key: &Option<Keypair>) -> Result<u64>
where
	R: Read,
	W: Write,
	H: DynDigest + ?Sized
{
	let (compressed_chunk, crc32, signature) = prepare_chunk(input, chunk_size, compression_algorithm, compression_level, hasher_map, signature_key)?;
	chunk_header.set_chunk_size(compressed_chunk.len() as u64);
	chunk_header.set_crc32(crc32);
	chunk_header.set_signature(signature);

	let mut written_bytes = 0;
	written_bytes += output.write(&chunk_header.encode_directly())?;
	written_bytes += output.write(&compressed_chunk)?;
	Ok(written_bytes as u64)
}

//TODO: optimization/code cleanup
fn write_encrypted_chunk<R, W, H>(
	input: &mut R,
	output: &mut W,
	chunk_size: usize,
	chunk_header: &mut ChunkHeader,
	compression_algorithm: &CompressionAlgorithm,
	compression_level: &u8,
	encryption_key: &Vec<u8>,
	encryption_algorithm: &EncryptionAlgorithm,
	hasher_map: &mut HashMap<HashType, Box<H>>,
	signature_key: &Option<Keypair>) -> Result<u64>
where
	R: Read,
	W: Write,
	H: DynDigest + ?Sized
{
	let (compressed_chunk, crc32, signature) = prepare_chunk(input, chunk_size, compression_algorithm, compression_level, hasher_map, signature_key)?;
	let encrypted_data = Encryption::encrypt_message(
		encryption_key,
		&compressed_chunk,
		chunk_header.chunk_number(),
		encryption_algorithm)?;
	chunk_header.set_chunk_size(encrypted_data.len() as u64);
	chunk_header.set_crc32(crc32);
	chunk_header.set_signature(signature);

	let mut written_bytes = 0;
	written_bytes += output.write(&chunk_header.encode_directly())?;
	written_bytes += output.write(&encrypted_data)?;
	Ok(written_bytes as u64)
}

/// reads the data from given source and writes the data as a segment to the given destination with the given options/values.
pub fn write_segment<R, W, H>(
	input: &mut R,
	output: &mut W,
	segment_header: &mut SegmentHeader,
	chunk_size: usize,
	chunk_header: &mut ChunkHeader,
	compression_algorithm: &CompressionAlgorithm,
	compression_level: &u8,
	segment_size: usize,
	encryption: &Option<(&Vec<u8>, EncryptionAlgorithm)>,
	hasher_map: &mut HashMap<HashType, Box<H>>,
	signature_key: &Option<Keypair>) -> Result<u64>
where
	R: Read,
	W: Write + Seek,
	H: DynDigest + ?Sized
{
	let mut written_bytes: u64 = 0;

	let segment_header_length = segment_header.encode_directly().len() as u64;

	let mut chunk_offsets = Vec::new();

	let _ = output.write(&segment_header.encode_directly())?;

	loop {
		if (written_bytes +
			chunk_size as u64 +
			DEFAULT_LENGTH_SEGMENT_FOOTER_EMPTY as u64 +
			(chunk_offsets.len()*8) as u64) > segment_size as u64 {

			if written_bytes == 0 {
				return Ok(written_bytes);
			} else {
				break;
			}
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
					hasher_map,
					signature_key) {
					Ok(data) => data,
					Err(e) => match e.get_kind() {
						ZffErrorKind::ReadEOF => {
							if written_bytes == 0 {
								return Ok(written_bytes);
							} else {
								break;
							}
						},
						_ => return Err(e),
					},
				};
				chunk_offsets.push(segment_header_length + written_bytes);
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
					hasher_map,
					signature_key) {
					Ok(data) => data,
					Err(e) => match e.get_kind() {
						ZffErrorKind::ReadEOF => {
							if written_bytes == 0 {
								return Ok(written_bytes);
							} else {
								break;
							}
						},
						_ => return Err(e),
					},
				};
				chunk_offsets.push(segment_header_length + written_bytes);
				written_bytes += written_in_chunk;
			}
		}
	}
	segment_header.set_footer_offset(written_bytes);
	let segment_footer = SegmentFooter::new(DEFAULT_SEGMENT_FOOTER_VERSION, chunk_offsets);
	written_bytes += output.write(&segment_footer.encode_directly())? as u64;
	segment_header.set_length_of_segment(segment_header_length + written_bytes);
	output.seek(SeekFrom::Start(0))?;
	written_bytes += output.write(&segment_header.encode_directly())? as u64;
	return Ok(written_bytes);
}

pub struct ZffReader<R: Read + Seek> {
	segments: HashMap<u64, Segment<R>> //<Segment number, Segment>
}

impl<R: Read + Seek> ZffReader<R> {
	pub fn new(mut segment_data: Vec<R>) -> Result<ZffReader<R>> {
		let mut map = HashMap::new();
		let mut current_chunk_number = 1;
		loop {
			let segment = match segment_data.pop() {
				Some(data) => Segment::new_from_reader(data, current_chunk_number)?,
				None => break,
			};
			let segment_number = segment.header().segment_number();
			current_chunk_number += segment.chunk_offsets().len() as u64;
			map.insert(segment_number, segment);
		}
		Ok(Self {
			segments: map
		})
	}
}