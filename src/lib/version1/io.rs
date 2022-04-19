// - STD
use std::collections::HashMap;
use std::time::{UNIX_EPOCH, SystemTime};
use std::io::{Read,Write,Seek,SeekFrom,Cursor, copy as io_copy};
use std::path::PathBuf;
use std::fs::{File, remove_file};


// - internal
use crate::{
	Result,
	header::version1::{MainHeader,SegmentHeader,ChunkHeader, HashValue, HashHeader},
	footer::version1::{SegmentFooter},
	CompressionAlgorithm,
	HeaderCoding,
	ZffError,
	ZffErrorKind,
	Encryption,
	HashType,
	Hash,
	EncryptionAlgorithm,
	Signature,
	file_extension_next_value,
	buffer_chunk,
};

use crate::version1::{
	Segment,
};

use crate::version1::{
	DEFAULT_LENGTH_SEGMENT_FOOTER_EMPTY,
	DEFAULT_SEGMENT_FOOTER_VERSION,
	ERROR_ZFFREADER_SEGMENT_NOT_FOUND,
	ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION,
	DEFAULT_HEADER_VERSION_CHUNK_HEADER,
	DEFAULT_HEADER_VERSION_SEGMENT_HEADER,
	FILE_EXTENSION_FIRST_VALUE,
	DEFAULT_HEADER_VERSION_HASH_VALUE_HEADER,
	DEFAULT_HEADER_VERSION_HASH_HEADER,
	ERROR_REWRITE_MAIN_HEADER,
	ED25519_DALEK_PUBKEY_LEN,
	ED25519_DALEK_SIGNATURE_LEN,
	ERROR_MISSING_SEGMENT
};

// - external
use crc32fast::Hasher as CRC32Hasher;
use ed25519_dalek::{Keypair};
use digest::DynDigest;
use zstd;
use lz4_flex;

/// The [ZffWriter] can be use to easily create a (segmented) zff image.
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
	/// creates a new [ZffWriter] with the given paramters.
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
			main_header,
			input,
			output_filenpath: output_filenpath.into(),
			read_bytes: 0,
			hasher_map,
			signature_key,
			encryption_key,
			header_encryption,
			current_chunk_no: 1,
			current_segment_no: 1,
			eof_reached: false,
		}
	}

	/// returns a reference to the underlying Keypair
	pub fn signature_key(&self) -> &Option<Keypair> {
		&self.signature_key
	}

	///writes the data to the appropriate files. The output files will be generated automatically by this method.
	pub fn generate_files(&mut self) -> Result<()> {
		let mut number_of_segments = 0;
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

	    output_file.write_all(&encoded_main_header)?;

	    //writes the first segment
	    let _ = self.write_segment(&mut output_file, encoded_main_header.len() as u64)?;
	    number_of_segments += 1;

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
	        number_of_segments += 1;
	    }

	    self.main_header.set_number_of_segments(number_of_segments);

	    self.eof_reached = true;

		let mut hash_values = Vec::new();
	    for (hash_type, hasher) in self.hasher_map.clone() {
	        let hash = hasher.finalize();
	        let mut hash_value = HashValue::new_empty(DEFAULT_HEADER_VERSION_HASH_VALUE_HEADER, hash_type);
	        hash_value.set_hash(hash.to_vec());
	        hash_values.push(hash_value);
	    }
	    let hash_header = HashHeader::new(DEFAULT_HEADER_VERSION_HASH_HEADER, hash_values);

	    //rewrite main_header with the correct number of bytes of the COMPRESSED data.
	    self.main_header.set_length_of_data(self.read_bytes);
	    self.main_header.set_hash_header(hash_header);
	    if let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) { self.main_header.set_acquisition_end(now.as_secs()) };
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
	    output_file.write_all(&encoded_main_header)?;

	    Ok(())
	}

	fn update_hasher(&mut self, buffer: &[u8]) {
		for hasher in self.hasher_map.values_mut() {
			hasher.update(buffer);
		}
	}

	fn get_crc32(buffer: &[u8]) -> u32 {
		let mut crc32_hasher = CRC32Hasher::new();
		crc32_hasher.update(buffer);
		crc32_hasher.finalize()
	}

	fn calculate_signature(&self, buffer: &[u8]) -> Option<[u8; ED25519_DALEK_SIGNATURE_LEN]> {
		self.signature_key.as_ref().map(|keypair| Signature::sign(keypair, buffer))
	}

	fn compress_buffer(&self, buf: Vec<u8>) -> Result<(Vec<u8>, bool)> {
		let mut compression_flag = false;
		let chunk_size = self.main_header.chunk_size();
		let compression_threshold = self.main_header.compression_header().threshold();

		match self.main_header.compression_header().algorithm() {
	    	CompressionAlgorithm::None => Ok((buf, compression_flag)),
	    	CompressionAlgorithm::Zstd => {
	    		let compression_level = *self.main_header.compression_header().level() as i32;
	    		let mut stream = zstd::stream::read::Encoder::new(buf.as_slice(), compression_level)?;
	    		let (compressed_data, _) = buffer_chunk(&mut stream, chunk_size * *self.main_header.compression_header().level() as usize)?;
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

	//returns (chunked_buffer_bytes, crc32_sig, Option<ED25519SIG>, CompressionFlag for ChunkHeader)
	fn prepare_chunk(&mut self) -> Result<(Vec<u8>, u32, Option<[u8; ED25519_DALEK_SIGNATURE_LEN]>, bool)> {
		let chunk_size = self.main_header.chunk_size();
	    let (buf, read_bytes) = buffer_chunk(&mut self.input, chunk_size)?;
	    self.read_bytes += read_bytes;
	    if buf.is_empty() {
	    	return Err(ZffError::new(ZffErrorKind::ReadEOF, ""));
	    };
	    self.update_hasher(&buf);
	    let crc32 = Self::get_crc32(&buf);
	    let signature = self.calculate_signature(&buf);

	    let (chunked_data, compression_flag) = self.compress_buffer(buf)?;
	    Ok((chunked_data, crc32, signature, compression_flag))
	}

	// returns written_bytes
	fn write_unencrypted_chunk<W>(&mut self, output: &mut W) -> Result<u64> 
	where
		W: Write,
	{
		let mut chunk_header = ChunkHeader::new_empty(DEFAULT_HEADER_VERSION_CHUNK_HEADER, self.current_chunk_no);
		let (compressed_chunk, crc32, signature, compression_flag) = self.prepare_chunk()?;
		chunk_header.set_chunk_size(compressed_chunk.len() as u64);
		chunk_header.set_crc32(crc32);
		chunk_header.set_signature(signature);
		if compression_flag {
			chunk_header.set_compression_flag()
		}

		let mut written_bytes = 0;
		written_bytes += output.write(&chunk_header.encode_directly())?;
		written_bytes += output.write(&compressed_chunk)?;
		Ok(written_bytes as u64)
	}

	// returns written_bytes
	fn write_encrypted_chunk<W>(&mut self, output: &mut W, encryption_key: Vec<u8>) -> Result<u64> 
	where
		W: Write,
	{
		let main_header = self.main_header.clone();
		let encryption_algorithm = match main_header.encryption_header() {
			Some(header) => header.algorithm(),
			None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionHeader, "")),
		};
		let mut chunk_header = ChunkHeader::new_empty(DEFAULT_HEADER_VERSION_CHUNK_HEADER, self.current_chunk_no); 
		let (compressed_chunk, crc32, signature, compression_flag) = self.prepare_chunk()?;
		let encrypted_data = Encryption::encrypt_message(
			encryption_key,
			&compressed_chunk,
			chunk_header.chunk_number(),
			encryption_algorithm)?;
		chunk_header.set_chunk_size(encrypted_data.len() as u64);
		chunk_header.set_crc32(crc32);
		chunk_header.set_signature(signature);
		if compression_flag {
			chunk_header.set_compression_flag()
		}

		let mut written_bytes = 0;
		written_bytes += output.write(&chunk_header.encode_directly())?;
		written_bytes += output.write(&encrypted_data)?;
		Ok(written_bytes as u64)
	}

	/// reads the data from given source and writes the data as a segment to the given destination with the given options/values.
	fn write_segment<W: Write + Seek>(
		&mut self,
		output: &mut W,
		seek_value: u64 // The seek value is a value of bytes you need to skip (e.g. if this segment contains a main_header, you have to skip the main_header..)
		) -> Result<u64>  // returns written_bytes
	{
		let mut written_bytes: u64 = 0;
		let mut segment_header = SegmentHeader::new_empty(
			DEFAULT_HEADER_VERSION_SEGMENT_HEADER,
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
		Ok(written_bytes)
	}

	/// returns a reference to the underlying [MainHeader](crate::header::MainHeader)
	pub fn main_header(&self) -> &MainHeader {
		&self.main_header
	}
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
		while let Some(data) = segment_data.pop() {
			let segment = Segment::new_from_reader(data)?;
			let segment_number = segment.header().segment_number();

			for chunk_number in segment.chunk_offsets().keys() {
				chunk_map.insert(*chunk_number, segment.header().segment_number());
			}

			segments.insert(segment_number, segment);
		}
		if segments.len() as u64 != main_header.number_of_segments() {
			return Err(ZffError::new(ZffErrorKind::MissingSegment, ERROR_MISSING_SEGMENT))
		};
		Ok(Self {
			main_header,
			segments,
			chunk_map,
			position: 0,
			encryption_key: None,
			encryption_algorithm: EncryptionAlgorithm::AES256GCMSIV, //is set to an encryption algorithm: this value will never be used without the self.encryption_key value.
		})
	}

	/// returns a reference to the underlying [MainHeader](crate::header::MainHeader);
	pub fn main_header(&self) -> &MainHeader {
		&self.main_header
	}

	/// tries to decrypt the encryption key.
	/// # Errors
	/// Returns a [ZffError] of kind [ZffErrorKind::DecryptionOfEncryptionKey](crate::ZffErrorKind), if the decryption of the encryption key has failed (in most cases: wrong password was used).
	/// Returns a [ZffError] of kind [ZffErrorKind::MissingEncryptionHeader](crate::ZffErrorKind), if no encryption header is present in the underlying [MainHeader](crate::header::MainHeader).
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

	/// verifies the authenticity of a specific chunk number
	/// returns true if the signature matches the data and false, if the data are corrupt.
	/// # Error
	/// This method fails, if the given chunk number is not present in the zff image
	/// with [ZffErrorKind::InvalidChunkNumber](crate::ZffErrorKind).
	/// This method fails, if the segment to the given chunk number is missing with
	/// [ZffErrorKind::MissingSegment](crate::ZffErrorKind).
	pub fn verify_chunk(&mut self, chunk_no: u64, publickey: [u8; ED25519_DALEK_PUBKEY_LEN]) -> Result<bool> {
		let segment = match self.chunk_map.get(&chunk_no) {
			Some(segment_no) => match self.segments.get_mut(segment_no) {
				Some(segment) => segment,
				None => return Err(ZffError::new(ZffErrorKind::MissingSegment, ERROR_MISSING_SEGMENT)),
			},
			None => return Err(ZffError::new(ZffErrorKind::InvalidChunkNumber, "")),
		};
		let compression_algorithm = self.main_header.compression_header().algorithm();
		match &self.encryption_key {
			None => segment.verify_chunk(chunk_no, compression_algorithm, publickey),
			Some(key) => segment.verify_chunk_decrypted(chunk_no, compression_algorithm, key, &self.encryption_algorithm, publickey),
		}
		
	}

	/// verifies all chunks and returns a Vec of chunk number, which are corrupt.
	/// # Error
	/// The method fails, if the image is corrupt (e.g. segments are missing) - unless ```ignore_missing_segments = true```.
	pub fn verify_all(&mut self, publickey: [u8; ED25519_DALEK_PUBKEY_LEN], ignore_missing_segments: bool) -> Result<Vec<u64>> {
		if self.segments.len() as u64 != self.main_header.number_of_segments() {
			return Err(ZffError::new(ZffErrorKind::MissingSegment, ERROR_MISSING_SEGMENT))
		};
		let mut corrupt_chunks = Vec::new();
		for chunk_number in self.chunk_map.clone().keys() {
			match self.verify_chunk(*chunk_number, publickey) {
				Ok(true) => (),
				Ok(false) => corrupt_chunks.push(*chunk_number),
				Err(e) => match e.get_kind() {
					ZffErrorKind::MissingSegment => if !ignore_missing_segments { return Err(e) },
					_ => return Err(e),
				},
			}
		}
		Ok(corrupt_chunks)
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
					error => return Err(std::io::Error::new(std::io::ErrorKind::Other, error.to_string())) 
				},
			},
			Some(key) => match segment.chunk_data_decrypted(current_chunk, compression_algorithm, key, &self.encryption_algorithm) {
				Ok(data) => data,
				Err(e) => match e.unwrap_kind() {
					ZffErrorKind::IoError(io_error) => return Err(io_error),
					error => return Err(std::io::Error::new(std::io::ErrorKind::Other, error.to_string())) 
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
					error => return Err(std::io::Error::new(std::io::ErrorKind::Other, error.to_string())) 
				},
			},
			Some(key) => match segment.chunk_data_decrypted(current_chunk, compression_algorithm, key, &self.encryption_algorithm) {
				Ok(data) => data,
				Err(e) => match e.unwrap_kind() {
					ZffErrorKind::IoError(io_error) => return Err(io_error),
					error => return Err(std::io::Error::new(std::io::ErrorKind::Other, error.to_string())) 
				},
			}
		};
			read_bytes += chunk_data.as_slice().read(&mut buffer[read_bytes..])?;
		}
		self.position += read_bytes as u64;
		Ok(read_bytes)
	}
}

impl<R: Read + Seek> Seek for ZffReader<R> {
	fn seek(&mut self, seek_from: SeekFrom) -> std::result::Result<u64, std::io::Error> {
		match seek_from {
			SeekFrom::Start(value) => self.position = value,
			SeekFrom::Current(value) => if self.position as i64 + value < 0 {
				return Err(std::io::Error::new(std::io::ErrorKind::Other, ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))
			} else if value >= 0 {
   					self.position += value as u64;
			} else {
				self.position -= value as u64;
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