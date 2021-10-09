// - STD
use std::collections::HashMap;
use std::time::{UNIX_EPOCH, SystemTime};
use std::io::{Read,Write,Seek,SeekFrom,Cursor, copy as io_copy};
use std::path::PathBuf;
use std::fs::{File, remove_file};


// - internal
use crate::{
	Result,
	header::{MainHeader,SegmentHeader,Segment,ChunkHeader, HashValue, HashHeader},
	footer::{SegmentFooter},
	CompressionAlgorithm,
	HeaderCoding,
	ZffError,
	ZffErrorKind,
	Encryption,
	HashType,
	Hash,
	EncryptionAlgorithm,
	file_extension_next_value,
};

use crate::{
	DEFAULT_LENGTH_SEGMENT_FOOTER_EMPTY,
	DEFAULT_SEGMENT_FOOTER_VERSION,
	ERROR_ZFFREADER_SEGMENT_NOT_FOUND,
	ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION,
	DEFAULT_CHUNK_HEADER_VERSION,
	DEFAULT_SEGMENT_HEADER_VERSION,
	FILE_EXTENSION_FIRST_VALUE,
	DEFAULT_HASH_VALUE_HEADER_VERSION,
	DEFAULT_HASH_HEADER_VERSION,
	ERROR_REWRITE_MAIN_HEADER,

};

// - external
use crc32fast::Hasher as CRC32Hasher;
use ed25519_dalek::{Keypair,Signer,SIGNATURE_LENGTH};
use digest::DynDigest;
use zstd;
use lz4_flex;


pub struct ZffWriter<R: Read> {
	main_header: MainHeader,
	input: R,
	output_filenpath: String,
	read_bytes: u64,
	hasher_map: HashMap<HashType, Box<dyn DynDigest>>,
	signature_key: Option<Keypair>,
	encryption_key: Option<Vec<u8>>,
	header_encryption: bool,
	current_chunk_no: u64,
	current_segment_no: u64,
	eof_reached: bool,
}

impl<R: Read> ZffWriter<R> {
	pub fn new<O: Into<String>>(
		main_header: MainHeader,
		input: R,
		output_filenpath: O,
		signature_key: Option<Keypair>,
		encryption_key: Option<Vec<u8>>,
		header_encryption: bool) -> ZffWriter<R> {
		let mut hasher_map = HashMap::new();
	    for value in main_header.hash_header().hash_values() {
	        let hasher = Hash::new_hasher(value.hash_type());
	        hasher_map.insert(value.hash_type().clone(), hasher);
	    };
		Self {
			main_header: main_header,
			input: input,
			output_filenpath: output_filenpath.into(),
			read_bytes: 0,
			hasher_map: hasher_map,
			signature_key: signature_key,
			encryption_key: encryption_key,
			header_encryption: header_encryption,
			current_chunk_no: 1,
			current_segment_no: 1,
			eof_reached: false,
		}
	}

	//TODO: optimization/code cleanup; //returns (chunked_buffer_bytes, crc32_sig, Option<ED25519SIG>)
	fn prepare_chunk(&mut self) -> Result<(Vec<u8>, u32, Option<[u8; SIGNATURE_LENGTH]>)> {
		let chunk_size = self.main_header.chunk_size();
	    let (buf, read_bytes) = buffer_chunk(&mut self.input, chunk_size)?;
	    self.read_bytes += read_bytes;
	    if buf.len() == 0 {
	    	return Err(ZffError::new(ZffErrorKind::ReadEOF, ""));
	    };
	    for hasher in self.hasher_map.values_mut() {
	    	hasher.update(&buf);
	    }
	    let mut crc32_hasher = CRC32Hasher::new();
	    crc32_hasher.update(&buf);
	    let crc32 = crc32_hasher.finalize();

	    let signature = match &self.signature_key {
	    	None => None,
	    	Some(keypair) => Some(keypair.sign(&buf).to_bytes()),
	    };

	    match self.main_header.compression_header().algorithm() {
	    	CompressionAlgorithm::None => return Ok((buf, crc32, signature)),
	    	CompressionAlgorithm::Zstd => {
	    		let compression_level = *self.main_header.compression_header().level() as i32;
	    		let mut stream = zstd::stream::read::Encoder::new(buf.as_slice(), compression_level)?;
	    		let (buf, _) = buffer_chunk(&mut stream, chunk_size * *self.main_header.compression_header().level() as usize)?;
	    		Ok((buf, crc32, signature))
	    	},
	    	CompressionAlgorithm::Lz4 => {
	    		let buffer = Vec::new();
	    		let mut compressor = lz4_flex::frame::FrameEncoder::new(buffer);
	    		io_copy(&mut buf.as_slice(), &mut compressor)?;
	    		let compressed_data = compressor.finish()?;
	    		Ok((compressed_data, crc32, signature))
	    	}
	    }
	}

	//TODO: optimization/code cleanup; // returns written_bytes
	fn write_unencrypted_chunk<W>(&mut self, output: &mut W) -> Result<u64> 
	where
		W: Write,
	{
		let mut chunk_header = ChunkHeader::new_empty(DEFAULT_CHUNK_HEADER_VERSION, self.current_chunk_no);
		let (compressed_chunk, crc32, signature) = self.prepare_chunk()?;
		chunk_header.set_chunk_size(compressed_chunk.len() as u64);
		chunk_header.set_crc32(crc32);
		chunk_header.set_signature(signature);

		let mut written_bytes = 0;
		written_bytes += output.write(&chunk_header.encode_directly())?;
		written_bytes += output.write(&compressed_chunk)?;
		Ok(written_bytes as u64)
	}

	//TODO: optimization/code cleanup ; //returns written_bytes
	fn write_encrypted_chunk<W>(&mut self, output: &mut W, encryption_key: Vec<u8>) -> Result<u64> 
	where
		W: Write,
	{
		let main_header = self.main_header.clone();
		let encryption_algorithm = match main_header.encryption_header() {
			Some(header) => header.algorithm(),
			None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionHeader, "")),
		};
		let mut chunk_header = ChunkHeader::new_empty(DEFAULT_CHUNK_HEADER_VERSION, self.current_chunk_no); 
		let (compressed_chunk, crc32, signature) = self.prepare_chunk()?;
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


	// TODO!
	// continues writing of data after an I/O interrupt of the INPUT stream.
	// pub fn continue(&mut self) -> Result<()> {
	//	unimplemented!()
	//}

	// continues writing of data to a segment after an I/O interrupt of the INPUT stream.
	//fn continue_segment<W: Write + Seek>(&mut self, _output: &mut W, _seek_value: u64) -> Result<u64> { //returns the written bytes of the SEGMENT
	//	unimplemented!()
	//}

	/// reads the data from given source and writes the data as a segment to the given destination with the given options/values.
	fn write_segment<W: Write + Seek>(
		&mut self,
		output: &mut W,
		seek_value: u64 // The seek value is a value of bytes you need to skip (e.g. if this segment contains a main_header, you have to skip the main_header..)
		) -> Result<u64>  // returns written_bytes
	{
		let mut written_bytes: u64 = 0;
		let mut segment_header = SegmentHeader::new_empty(
			DEFAULT_SEGMENT_HEADER_VERSION,
			self.main_header.unique_identifier(),
			self.current_segment_no);
		let segment_header_length = segment_header.encode_directly().len() as u64;
		let chunk_size = self.main_header.chunk_size();
		let segment_size = self.main_header.segment_size();

		let mut chunk_offsets = Vec::new();

		let _ = output.write(&segment_header.encode_directly())?;
		loop {
			if (written_bytes +
				chunk_size as u64 +
				DEFAULT_LENGTH_SEGMENT_FOOTER_EMPTY as u64 +
				(chunk_offsets.len()*8) as u64) > segment_size-seek_value as u64 {

				if written_bytes == 0 {
					return Ok(written_bytes);
				} else {
					break;
				}
			};
			chunk_offsets.push(seek_value + segment_header_length + written_bytes);
			let encryption_key = self.encryption_key.clone();
			match encryption_key {
				None => {
					let written_in_chunk = match self.write_unencrypted_chunk(output) {
						Ok(data) => data,
						Err(e) => match e.get_kind() {
							ZffErrorKind::ReadEOF => {
								if written_bytes == 0 {
									return Ok(written_bytes);
								} else {
									chunk_offsets.pop();
									break;
								}
							},
							ZffErrorKind::InterruptedInputStream => {
								chunk_offsets.pop();
								break;
							},
							_ => return Err(e),
						},
					};
					written_bytes += written_in_chunk;
				},
				Some(encryption) => {
					let written_in_chunk = match self.write_encrypted_chunk(output, encryption.to_vec()) {
						Ok(data) => data,
						Err(e) => match e.get_kind() {
							ZffErrorKind::ReadEOF => {
								if written_bytes == 0 {
  									return Ok(written_bytes);
								} else {
									chunk_offsets.pop();
									break;
								}
							},
							_ => return Err(e),
						},
					};
					written_bytes += written_in_chunk;
				}
			}
			self.current_chunk_no += 1;
		}
		segment_header.set_footer_offset(seek_value + segment_header_length + written_bytes);
		let segment_footer = SegmentFooter::new(DEFAULT_SEGMENT_FOOTER_VERSION, chunk_offsets);
		written_bytes += output.write(&segment_footer.encode_directly())? as u64;
		segment_header.set_length_of_segment(segment_header_length + written_bytes);
		output.seek(SeekFrom::Start(seek_value))?;
		written_bytes += output.write(&segment_header.encode_directly())? as u64;
		return Ok(written_bytes);
	}

	pub fn generate_files(&mut self) -> Result<()> {
		let main_header_size = self.main_header.get_encoded_size();
		if (self.main_header.segment_size() as usize) < main_header_size {
	        return Err(ZffError::new(ZffErrorKind::SegmentSizeToSmall, ""));
	    };	    
	    let mut first_segment_filename = PathBuf::from(&self.output_filenpath);
	    let mut file_extension = String::from(FILE_EXTENSION_FIRST_VALUE);
	    first_segment_filename.set_extension(&file_extension);
	    let mut output_file = File::create(&first_segment_filename)?;

	    let encryption_key = &self.encryption_key.clone();

	    let encoded_main_header = match &encryption_key {
	        None => self.main_header.encode_directly(),
	        Some(key) => if self.header_encryption {
	          self.main_header.encode_encrypted_header_directly(key)? 
	        } else {
	            self.main_header.encode_directly()
	        } 
	    };

	    output_file.write(&encoded_main_header)?;

	    //writes the first segment
	    let _ = self.write_segment(&mut output_file, encoded_main_header.len() as u64)?;

	    loop {
	    	self.current_segment_no += 1;
	    	file_extension = file_extension_next_value(&file_extension)?;
	    	let mut segment_filename = PathBuf::from(&self.output_filenpath);
	    	segment_filename.set_extension(&file_extension);
	    	let mut output_file = File::create(&segment_filename)?;

	    	let written_bytes_in_segment = self.write_segment(&mut output_file, 0)?;
	    	if written_bytes_in_segment == 0 {
	            let _ = remove_file(segment_filename);
	            break;
	        }
	    }

	    self.eof_reached = true;

		let mut hash_values = Vec::new();
	    for (hash_type, hasher) in self.hasher_map.clone() {
	        let hash = hasher.finalize();
	        let mut hash_value = HashValue::new_empty(DEFAULT_HASH_VALUE_HEADER_VERSION, hash_type);
	        hash_value.set_hash(hash.to_vec());
	        hash_values.push(hash_value);
	    }
	    let hash_header = HashHeader::new(DEFAULT_HASH_HEADER_VERSION, hash_values);

	    //rewrite main_header with the correct number of bytes of the COMPRESSED data.
	    self.main_header.set_length_of_data(self.read_bytes);
	    self.main_header.set_hash_header(hash_header);
	    match SystemTime::now().duration_since(UNIX_EPOCH) {
	        Ok(now) => self.main_header.set_acquisition_end(now.as_secs()),
	        Err(_) => ()
	    };
	    output_file.rewind()?;
	    let encoded_main_header = match &encryption_key {
	        None => self.main_header.encode_directly(),
	        Some(key) => if self.header_encryption {
	          match self.main_header.encode_encrypted_header_directly(key) {
	                Ok(data) => if data.len() == encoded_main_header.len() {
	                    data
	                } else {
	                    return Err(ZffError::new(ZffErrorKind::MainHeaderEncryptionError, ERROR_REWRITE_MAIN_HEADER))
	                },
	                Err(e) => return Err(e)
	            }  
	        } else {
	            self.main_header.encode_directly()
	        }  
	    };
	    output_file.write(&encoded_main_header)?;

	    Ok(())
	}
}

// returns the buffer with the read bytes and the number of bytes which was read.
fn buffer_chunk<R>(
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
    return Ok((buf, bytes_read as u64))
}

/// This is a reader struct which implements [std::io::Read] to read data from a zff image.
pub struct ZffReader<R: 'static +  Read + Seek> {
	main_header: MainHeader,
	segments: HashMap<u64, Segment<R>>, //<Segment number, Segment>
	chunk_map: HashMap<u64, u64>, //<chunk_number, segment_number> for better runtime performance.
	position: u64,
	encryption_key: Option<Vec<u8>>,
	encryption_algorithm: EncryptionAlgorithm,
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
			encryption_key: None,
			encryption_algorithm: EncryptionAlgorithm::AES256GCMSIV, //is set to an encryption algorithm: this value will never be used without the self.encryption_key value.
		})
	}

	pub fn main_header(&self) -> &MainHeader {
		&self.main_header
	}

	pub fn decrypt_encryption_key<P: AsRef<[u8]>>(&mut self, password: P) -> Result<()> {
		match self.main_header.encryption_header() {
			Some(header) => {
				let key = header.decrypt_encryption_key(password)?;
				let algorithm = header.algorithm();
				self.encryption_key = Some(key);
				self.encryption_algorithm = algorithm.clone();
				//test the decryption
				let mut buffer = [0u8; 1];
				match self.read(&mut buffer) {
					Ok(_) => (),
					Err(_) => return Err(ZffError::new(ZffErrorKind::DecryptionOfEncryptionKey, ""))
				};
				self.seek(SeekFrom::Start(0))?;
			},
			None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionHeader, "")),
		}
		Ok(())
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

		let chunk_data = match &self.encryption_key {
			None => match segment.chunk_data(current_chunk, compression_algorithm) {
				Ok(data) => data,
				Err(e) => match e.unwrap_kind() {
					ZffErrorKind::IoError(io_error) => return Err(io_error),
					error @ _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, error.to_string())) 
				},
			},
			Some(key) => match segment.chunk_data_decrypted(current_chunk, compression_algorithm, key, &self.encryption_algorithm) {
				Ok(data) => data,
				Err(e) => match e.unwrap_kind() {
					ZffErrorKind::IoError(io_error) => return Err(io_error),
					error @ _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, error.to_string())) 
				},
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
			let chunk_data = match &self.encryption_key {
			None => match segment.chunk_data(current_chunk, compression_algorithm) {
				Ok(data) => data,
				Err(e) => match e.unwrap_kind() {
					ZffErrorKind::IoError(io_error) => return Err(io_error),
					error @ _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, error.to_string())) 
				},
			},
			Some(key) => match segment.chunk_data_decrypted(current_chunk, compression_algorithm, key, &self.encryption_algorithm) {
				Ok(data) => data,
				Err(e) => match e.unwrap_kind() {
					ZffErrorKind::IoError(io_error) => return Err(io_error),
					error @ _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, error.to_string())) 
				},
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