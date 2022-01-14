// - STD
use std::io::{Read, Seek, SeekFrom, copy as io_copy, Cursor};
use std::path::PathBuf;
use std::fs::{File, canonicalize};
use std::collections::{HashMap};
use std::time::{SystemTime};

// - internal
use crate::version2::{
	header::{FileHeader, FileType, MainHeader, ChunkHeader, HashValue, HashHeader},
	footer::{FileFooter},
};
use crate::{
	Result,
	buffer_chunk,
	HeaderCoding,
	ValueEncoder,
	HashType,
	Hash,
	Signature,
	Encryption,
	CompressionAlgorithm,
	ZffError,
	ZffErrorKind,
	ED25519_DALEK_SIGNATURE_LEN,
	DEFAULT_HEADER_VERSION_CHUNK_HEADER,
	DEFAULT_HEADER_VERSION_HASH_VALUE_HEADER,
	DEFAULT_HEADER_VERSION_HASH_HEADER,
	DEFAULT_FOOTER_VERSION_FILE_FOOTER,
};

// - external
use digest::DynDigest;
use crc32fast::Hasher as CRC32Hasher;
use ed25519_dalek::{Keypair};
use time::{OffsetDateTime};

pub struct FileEncoder {
	/// An encoded [FileHeader].
	encoded_header: Vec<u8>,
	/// remaining bytes of the encoded header to read. This is only (internally) used, if you will use the [Read] implementation of [FileEncoder].
	encoded_header_remaining_bytes: usize,
	/// The underlying [File](std::fs::File) object to read from.
	underlying_file: File,
	/// optinal signature key, to sign the data with the given keypair
	signature_key: Option<Keypair>,
	/// optinal encryption key, to encrypt the data with the given key
	encryption_key: Option<Vec<u8>>,
	/// HashMap for the Hasher objects to calculate the cryptographically hash values for this file. 
	hasher_map: HashMap<HashType, Box<dyn DynDigest>>,
	main_header: MainHeader,
	/// The Type of this file
	file_type: FileType,
	/// The first chunk number for this file.
	initial_chunk_number: u64,
	/// The current chunk number
	current_chunk_number: u64,
	/// The number of bytes, which were read from the underlying file.
	read_bytes_underlying_data: u64,
	/// Path were the symlink links to. Note: This should be None, if this is not a symlink.
	symlink_real_path: Option<PathBuf>,
	/// The encoded footer, only used in Read implementation
	encoded_footer: Vec<u8>,
	encoded_footer_remaining_bytes: usize,
	/// data of current chunk (only used in Read implementation)
	current_chunked_data: Option<Vec<u8>>,
	current_chunked_data_remaining_bytes: usize,
	acquisition_start: u64,
	acquisition_end: u64,
}

impl FileEncoder {
	pub fn new(
		file_header: FileHeader,
		file: File,
		hash_types: Vec<HashType>,
		encryption_key: Option<Vec<u8>>,
		signature_key: Option<Keypair>,
		main_header: MainHeader,
		current_chunk_number: u64,
		symlink_real_path: Option<PathBuf>) -> FileEncoder {
		let encoded_header = file_header.encode_directly();
		let mut hasher_map = HashMap::new();
	    for h_type in hash_types {
	        let hasher = Hash::new_hasher(&h_type);
	        hasher_map.insert(h_type.clone(), hasher);
	    };
		Self {
			encoded_header_remaining_bytes: encoded_header.len(),
			encoded_header: encoded_header,
			underlying_file: file,
			hasher_map: hasher_map,
			encryption_key: encryption_key,
			signature_key: signature_key,
			main_header: main_header,
			file_type: file_header.file_type(),
			initial_chunk_number: current_chunk_number,
			current_chunk_number: current_chunk_number,
			read_bytes_underlying_data: 0,
			symlink_real_path: symlink_real_path,
			current_chunked_data: None,
			current_chunked_data_remaining_bytes: 0,
			encoded_footer: Vec::new(),
			encoded_footer_remaining_bytes: 0,
			acquisition_start: 0,
			acquisition_end: 0,
		}
	}

	fn update_hasher(&mut self, buffer: &Vec<u8>) {
		for hasher in self.hasher_map.values_mut() {
			hasher.update(buffer);
		}
	}

	fn calculate_crc32(buffer: &Vec<u8>) -> u32 {
		let mut crc32_hasher = CRC32Hasher::new();
		crc32_hasher.update(buffer);
		let crc32 = crc32_hasher.finalize();
		crc32
	}

	fn calculate_signature(&self, buffer: &Vec<u8>) -> Option<[u8; ED25519_DALEK_SIGNATURE_LEN]> {
		match &self.signature_key {
			None => None,
			Some(keypair) => Some(Signature::sign(keypair, buffer)),
		}
	}

	// returns compressed/read bytes + flag if bytes are be compressed or not-
	fn compress_buffer(&self, buf: Vec<u8>) -> Result<(Vec<u8>, bool)> {
		let mut compression_flag = false;
		let chunk_size = self.main_header.chunk_size();
		let compression_threshold = self.main_header.compression_header().threshold();

		match self.main_header.compression_header().algorithm() {
	    	CompressionAlgorithm::None => return Ok((buf, compression_flag)),
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

	// returns the encoded header
	pub fn get_encoded_header(&mut self) -> Vec<u8> {
		self.acquisition_start = OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64;
		self.encoded_header.clone()
	}

	//returns the encoded Chunk - this method will increment the self.current_chunk_number automatically.
	pub fn get_next_chunk(&mut self) -> Result<Vec<u8>> {
		match self.file_type {
			FileType::Directory => return Err(ZffError::new(ZffErrorKind::NotAvailableForFileType, "Directory")),
			FileType::Symlink => {
				match &self.symlink_real_path {
					//TODO: Test if this is possible to decode (empty String?!)
					None => return Ok(String::from("").encode_directly()),
					Some(link_path) => {
						let symlink_real = canonicalize(link_path)?;
						return Ok(symlink_real.to_string_lossy().encode_directly());
					}
				}
			},
			FileType::File => ()
		}
		let mut chunk = Vec::new();

		// prepare chunked data:
	    let chunk_size = self.main_header.chunk_size();
	    let (buf, read_bytes) = buffer_chunk(&mut self.underlying_file, chunk_size as usize)?;
	    self.read_bytes_underlying_data += read_bytes;
	    if buf.len() == 0 {
	    	return Err(ZffError::new(ZffErrorKind::ReadEOF, ""));
	    };
	    self.update_hasher(&buf);
	    let crc32 = Self::calculate_crc32(&buf);
	    let signature = self.calculate_signature(&buf);

	    let (mut chunked_data, compression_flag) = self.compress_buffer(buf)?;

	    // prepare chunk header:
	    let mut chunk_header = ChunkHeader::new_empty(DEFAULT_HEADER_VERSION_CHUNK_HEADER, self.current_chunk_number);
	    chunk_header.set_chunk_size(chunked_data.len() as u64);
	    chunk_header.set_crc32(crc32);
	    chunk_header.set_signature(signature);
	    if compression_flag {
			chunk_header.set_compression_flag()
		}
		chunk.append(&mut chunk_header.encode_directly());
		match &self.encryption_key {
			Some(encryption_key) => {
				let encryption_algorithm = match self.main_header.encryption_header() {
					Some(header) => header.algorithm(),
					None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionHeader, "")),
				};
				let mut encrypted_data = Encryption::encrypt_message(
					encryption_key,
					&chunked_data,
					chunk_header.chunk_number(),
					encryption_algorithm)?;
				chunk.append(&mut encrypted_data);
			},
			None => chunk.append(&mut chunked_data),
		}
		self.current_chunk_number += 1;
	    return Ok(chunk);
	}

	pub fn get_encoded_footer(&mut self) -> Vec<u8> {
		self.acquisition_end = OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64;
		let mut hash_values = Vec::new();
		for (hash_type, hasher) in self.hasher_map.clone() {
			let hash = hasher.finalize();
			let mut hash_value = HashValue::new_empty(DEFAULT_HEADER_VERSION_HASH_VALUE_HEADER, hash_type);
			hash_value.set_hash(hash.to_vec());
			hash_values.push(hash_value);
		}
		let hash_header = HashHeader::new(DEFAULT_HEADER_VERSION_HASH_HEADER, hash_values);
		let footer = FileFooter::new(
			DEFAULT_FOOTER_VERSION_FILE_FOOTER,
			self.acquisition_start,
			self.acquisition_end,
			hash_header,
			self.initial_chunk_number,
			self.current_chunk_number - self.initial_chunk_number,
			self.read_bytes_underlying_data as u64,
			);
		footer.encode_directly()
	}
}

/// this implement Read for [FileEncoder]. This implementation should only used for a single zff segment file.
impl Read for FileEncoder {
	fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
		let mut read_bytes = 0;
		//read encoded header, if there are remaining bytes to read.
        match self.encoded_header_remaining_bytes {
            remaining_bytes @ 1.. => {
                let mut inner_read_bytes = 0;
                let mut inner_cursor = Cursor::new(&self.encoded_header);
                inner_cursor.seek(SeekFrom::End(remaining_bytes as i64 * -1))?;
                inner_read_bytes += inner_cursor.read(&mut buf[read_bytes..])?;
                self.encoded_header_remaining_bytes -= inner_read_bytes;
                read_bytes += inner_read_bytes;
            },
            _ => (),
        }
        loop {
        	if read_bytes == buf.len() {
        		self.encoded_footer = self.get_encoded_footer();
        		self.encoded_footer_remaining_bytes = self.encoded_footer.len();
				break;
			};
        	match &self.current_chunked_data {
        		Some(data) => {
        			let mut inner_read_bytes = 0;
        			let mut inner_cursor = Cursor::new(&data);
        			inner_cursor.seek(SeekFrom::End(self.current_chunked_data_remaining_bytes as i64 * -1))?;
        			inner_read_bytes += inner_cursor.read(&mut buf[read_bytes..])?;
        			self.current_chunked_data_remaining_bytes -= inner_read_bytes;
        			if self.current_chunked_data_remaining_bytes < 1 {
        				self.current_chunked_data = None;
        			}
        			read_bytes += inner_read_bytes;
        		},
        		None => {
        			match self.get_next_chunk() {
        				Ok(chunk) => {
        					self.current_chunked_data_remaining_bytes = chunk.len();
        					self.current_chunked_data = Some(chunk);
        				},
        				Err(e) => match e.unwrap_kind() {
        					ZffErrorKind::ReadEOF => break,
        					ZffErrorKind::NotAvailableForFileType => break,
        					ZffErrorKind::IoError(ioe) => return Err(ioe),
        					e @ _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
        				}
        			}
        		}
        	}
        }
        //read encoded footer, if there are remaining bytes to read.
        match self.encoded_footer_remaining_bytes {
            remaining_bytes @ 1.. => {
                let mut inner_read_bytes = 0;
                let mut inner_cursor = Cursor::new(&self.encoded_footer);
                inner_cursor.seek(SeekFrom::End(remaining_bytes as i64 * -1))?;
                inner_read_bytes += inner_cursor.read(&mut buf[read_bytes..])?;
                self.encoded_footer_remaining_bytes -= inner_read_bytes;
                read_bytes += inner_read_bytes;
            },
            _ => (),
        }
        Ok(read_bytes)
	}
}