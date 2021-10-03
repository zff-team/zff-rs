// - STD
use std::collections::HashMap;
use std::io::{Read,Write,Seek,SeekFrom,Cursor};


// - internal
use crate::{
	Result,
	header::{MainHeader,SegmentHeader,SegmentFooter,Segment,ChunkHeader},
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
	ERROR_ZFFREADER_SEGMENT_NOT_FOUND,
	ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION,
};

// - external
use crc32fast::Hasher as CRC32Hasher;
use ed25519_dalek::{Keypair,Signer,SIGNATURE_LENGTH};
use digest::DynDigest;


fn buffer_chunk<R>(
	input: &mut R,
	chunk_size: usize,
	) -> Result<(Vec<u8>, u64)> // returns the buffer with the read bytes and the number of bytes which was read.
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
    return Ok((buf, bytes_read as u64))
}

//TODO: optimization/code cleanup
fn prepare_chunk<R, H>(
	input: &mut R,
	chunk_size: usize,
	algorithm: &CompressionAlgorithm,
	compression_level: &u8,
	hasher_map: &mut HashMap<HashType, Box<H>>,
	signature_key: &Option<Keypair>) -> Result<(Vec<u8>, u64, u32, Option<[u8; SIGNATURE_LENGTH]>)> //returns (chunked_buffer_bytes, read_bytes, crc32_sig, Option<ED25519SIG>)
where
    R: Read,
    H: DynDigest + ?Sized
{
    let (buf, read_bytes) = buffer_chunk(input, chunk_size)?;
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
    	CompressionAlgorithm::None => return Ok((buf, read_bytes, crc32, signature)),
    	CompressionAlgorithm::Zstd => {
    		let mut stream = zstd::stream::read::Encoder::new(buf.as_slice(), *compression_level as i32)?;
    		let (buf, _) = buffer_chunk(&mut stream, chunk_size*4)?;
    		Ok((buf, read_bytes, crc32, signature))
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
	signature_key: &Option<Keypair>) -> Result<(u64, u64)> // returns (written_bytes, read_bytes)
where
	R: Read,
	W: Write,
	H: DynDigest + ?Sized
{
	let (compressed_chunk, read_bytes, crc32, signature) = prepare_chunk(input, chunk_size, compression_algorithm, compression_level, hasher_map, signature_key)?;
	chunk_header.set_chunk_size(compressed_chunk.len() as u64);
	chunk_header.set_crc32(crc32);
	chunk_header.set_signature(signature);

	let mut written_bytes = 0;
	written_bytes += output.write(&chunk_header.encode_directly())?;
	written_bytes += output.write(&compressed_chunk)?;
	Ok((written_bytes as u64, read_bytes))
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
	signature_key: &Option<Keypair>) -> Result<(u64, u64)> //returns (written_bytes, read_bytes)
where
	R: Read,
	W: Write,
	H: DynDigest + ?Sized
{
	let (compressed_chunk, read_bytes, crc32, signature) = prepare_chunk(input, chunk_size, compression_algorithm, compression_level, hasher_map, signature_key)?;
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
	Ok((written_bytes as u64, read_bytes))
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
	signature_key: &Option<Keypair>,
	seek_value: u64 // The seek value is a value of bytes you need to skip (e.g. if this segment contains a main_header, you have to skip the main_header..)
	) -> Result<(u64, u64)>  // returns (written_bytes, read_bytes)
where
	R: Read,
	W: Write + Seek,
	H: DynDigest + ?Sized
{
	let mut written_bytes: u64 = 0;
	let mut read_bytes: u64 = 0;

	let segment_header_length = segment_header.encode_directly().len() as u64;

	let mut chunk_offsets = Vec::new();

	let _ = output.write(&segment_header.encode_directly())?;

	loop {
		if (written_bytes +
			chunk_size as u64 +
			DEFAULT_LENGTH_SEGMENT_FOOTER_EMPTY as u64 +
			(chunk_offsets.len()*8) as u64) > segment_size as u64 {

			if written_bytes == 0 {
				return Ok((written_bytes, read_bytes));
			} else {
				break;
			}
		};
		match encryption {
			None => {
				let (written_in_chunk, read_in_chunk) = match write_unencrypted_chunk(
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
								return Ok((written_bytes, read_bytes));
							} else {
								break;
							}
						},
						_ => return Err(e),
					},
				};
				written_bytes += written_in_chunk;
				read_bytes += read_in_chunk;
			},
			Some(ref encryption) => {
				let (written_in_chunk, read_in_chunk) = match write_encrypted_chunk(
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
								return Ok((written_bytes, read_bytes));
							} else {
								break;
							}
						},
						_ => return Err(e),
					},
				};
				written_bytes += written_in_chunk;
				read_bytes += read_in_chunk;
			}
		}
		chunk_offsets.push(seek_value + segment_header_length + written_bytes);
		chunk_header.next_number();
	}
	segment_header.set_footer_offset(seek_value + segment_header_length + written_bytes);
	let segment_footer = SegmentFooter::new(DEFAULT_SEGMENT_FOOTER_VERSION, chunk_offsets);
	written_bytes += output.write(&segment_footer.encode_directly())? as u64;
	segment_header.set_length_of_segment(segment_header_length + written_bytes);
	output.seek(SeekFrom::Start(seek_value))?;
	written_bytes += output.write(&segment_header.encode_directly())? as u64;
	return Ok((written_bytes, read_bytes));
}

/// This is a reader struct which implements [std::io::Read] to read data from a zff image.
pub struct ZffReader<R: 'static +  Read + Seek> {
	main_header: MainHeader,
	segments: HashMap<u64, Segment<R>>, //<Segment number, Segment>
	chunk_map: HashMap<u64, u64>, //<chunk_number, segment_number> for better runtime performance.
	position: u64,
}

impl<R: 'static +  Read + Seek> ZffReader<R> {
	/// creates a new ZffReader instance.
	pub fn new(mut segment_data: Vec<R>, main_header: MainHeader) -> Result<ZffReader<R>> {
		let mut segments = HashMap::new();
		let mut chunk_map = HashMap::new();
		loop {
			let segment = match segment_data.pop() {
				Some(data) => Segment::new_from_reader(data)?,
				None => break,
			};
			let segment_number = segment.header().segment_number();

			for chunk_number in segment.chunk_offsets().keys() {
				chunk_map.insert(*chunk_number, segment.header().segment_number());
			}

			segments.insert(segment_number, segment);
		}
		Ok(Self {
			main_header: main_header,
			segments: segments,
			chunk_map: chunk_map,
			position: 0,
		})
	}

	pub fn main_header(&self) -> &MainHeader {
		&self.main_header
	}
}

impl<R: Read + Seek> Read for ZffReader<R> {
	fn read(&mut self, buffer: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
 		let chunk_size = self.main_header.chunk_size(); // size of chunks
		let mut current_chunk = self.position / chunk_size as u64 + 1; // the first chunk to read. The first chunk is 1, so we need to add +1.
		let inner_chunk_start_position = self.position % chunk_size as u64; // the inner chunk position
		let mut read_bytes = 0; // number of bytes which are written to buffer
		let compression_algorithm = self.main_header.compression_header().algorithm();
		let segment = match self.chunk_map.get(&current_chunk) {
			Some(segment_no) => match self.segments.get_mut(segment_no) {
				Some(segment) => segment,
				None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
			},
			None => return Ok(0),
		};
		let chunk_data = match segment.chunk_data(current_chunk, compression_algorithm) {
			Ok(data) => data,
			Err(e) => match e.unwrap_kind() {
				ZffErrorKind::IoError(io_error) => return Err(io_error),
				error @ _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, error.to_string())) 
			}
		};
		let mut cursor = Cursor::new(chunk_data);
		cursor.set_position(inner_chunk_start_position);
		let curr_read_bytes = cursor.read(buffer)?;
		read_bytes += curr_read_bytes;
		loop {
			if read_bytes == buffer.len() {
				break;
			};
			current_chunk += 1;
			let segment = match self.chunk_map.get(&current_chunk) {
				Some(segment_no) => match self.segments.get_mut(segment_no) {
					Some(segment) => segment,
					None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
				},
				None => break,
			};
			let chunk_data = match segment.chunk_data(current_chunk, compression_algorithm) {
				Ok(data) => data,
				Err(e) => match e.unwrap_kind() {
					ZffErrorKind::IoError(io_error) => return Err(io_error),
					error @ _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, error.to_string())) 
				}
			};
			read_bytes += chunk_data.as_slice().read(&mut buffer[read_bytes..])?;
		}
		self.position += read_bytes as u64;
		return Ok(read_bytes);
	}
}

impl<R: Read + Seek> Seek for ZffReader<R> {
	fn seek(&mut self, seek_from: SeekFrom) -> std::result::Result<u64, std::io::Error> {
		match seek_from {
			SeekFrom::Start(value) => self.position = value,
			SeekFrom::Current(value) => if self.position as i64 + value < 0 {
				return Err(std::io::Error::new(std::io::ErrorKind::Other, ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))
			} else {
				if value >= 0 {
					self.position += value as u64;
				} else {
					self.position -= value as u64;
				}
			},
			SeekFrom::End(value) => if self.position as i64 + value < 0 {
				return Err(std::io::Error::new(std::io::ErrorKind::Other, ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))
			} else {
				let end = self.main_header().length_of_data();
				if value >= 0 {
					self.position = end + value as u64;
				} else {
					self.position = end - value as u64;
				}
			},
		}
		Ok(self.position)
	}
}