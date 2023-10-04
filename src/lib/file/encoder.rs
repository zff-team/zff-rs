// - STD
use std::io::{Read, Cursor};
use std::path::PathBuf;

use std::collections::{HashMap};
use std::time::{SystemTime};

// - internal
use crate::{
	header::{FileHeader, FileType, HashHeader, ChunkHeader, HashValue, EncryptionInformation, ObjectHeader, DeduplicationChunkMap},
	footer::{FileFooter},
};
use crate::{
	Result,
	io::{buffer_chunk, calculate_crc32, compress_buffer, check_same_byte},
	HeaderCoding,
	ValueEncoder,
	HashType,
	Hash,
	Encryption,
	ZffError,
	ZffErrorKind,
	DEFAULT_HEADER_VERSION_HASH_VALUE_HEADER,
	DEFAULT_HEADER_VERSION_HASH_HEADER,
	DEFAULT_FOOTER_VERSION_FILE_FOOTER,
};

// - external
use digest::DynDigest;
use ed25519_dalek::{SigningKey};
use time::{OffsetDateTime};

/// The [FileEncoder] can be used to encode a [crate::file::File].
pub struct FileEncoder {
	/// The appropriate [FileHeader].
	file_header: FileHeader,
	/// remaining bytes of the encoded header to read. This is only (internally) used, if you will use the [Read] implementation of [FileEncoder].
	encoded_header_remaining_bytes: usize,
	/// The appropriate [ObjectHeader].
	object_header: ObjectHeader,
	/// The underlying [File](std::fs::File) object to read from.
	underlying_file: Box<dyn Read>,
	/// optinal signature key, to sign the data with the given SigningKey
	signature_key: Option<SigningKey>,
	/// optional encryption information, to encrypt the data with the given key and algorithm
	encryption_information: Option<EncryptionInformation>,
	/// HashMap for the Hasher objects to calculate the cryptographically hash values for this file. 
	hasher_map: HashMap<HashType, Box<dyn DynDigest>>,
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
	hard_link_filenumber: Option<u64>,
	encoded_directory_children: Vec<u8>,
}

impl FileEncoder {
	/// creates a new [FileEncoder] with the given values.
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		file_header: FileHeader,
		object_header: ObjectHeader,
		file: Box<dyn Read>,
		hash_types: Vec<HashType>,
		encryption_information: Option<EncryptionInformation>,
		signature_key: Option<SigningKey>,
		current_chunk_number: u64,
		symlink_real_path: Option<PathBuf>,
		hard_link_filenumber: Option<u64>,
		directory_children: Vec<u64>) -> Result<FileEncoder> {

		let encoded_header = if let Some(enc_info) = &encryption_information {
	    	file_header.encode_encrypted_header_directly(enc_info)?
	    } else {
	    	file_header.encode_directly()
	    };
		
		let mut hasher_map = HashMap::new();
	    for h_type in hash_types {
	        let hasher = Hash::new_hasher(&h_type);
	        hasher_map.insert(h_type.clone(), hasher);
	    };
	    let encoded_directory_children = if directory_children.is_empty() {
	    	Vec::new()
	    } else {
	    	directory_children.encode_directly()
	    };
	    let file_type = file_header.file_type.clone();
		Ok(Self {
			encoded_header_remaining_bytes: encoded_header.len(),
			file_header,
			object_header,
			underlying_file: Box::new(file),
			hasher_map,
			encryption_information,
			signature_key,
			file_type,
			initial_chunk_number: current_chunk_number,
			current_chunk_number,
			read_bytes_underlying_data: 0,
			symlink_real_path,
			current_chunked_data: None,
			current_chunked_data_remaining_bytes: 0,
			encoded_footer: Vec::new(),
			encoded_footer_remaining_bytes: 0,
			acquisition_start: 0,
			acquisition_end: 0,
			hard_link_filenumber,
			encoded_directory_children,
		})
	}

	fn update_hasher(&mut self, buffer: &[u8]) {
		for hasher in self.hasher_map.values_mut() {
			hasher.update(buffer);
		}
	}

	/// returns the underlying encoded header
	pub fn get_encoded_header(&mut self) -> Vec<u8> {
		if self.acquisition_start == 0 {
			self.acquisition_start = OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64;
		}
		if let Some(enc_info) = &self.encryption_information {
			//unwrap should be safe here, because we have already testet this before.
	    	self.file_header.encode_encrypted_header_directly(enc_info).unwrap()
	    } else {
	    	self.file_header.encode_directly()
	    }
	}

	/// returns the encoded chunk - this method will increment the self.current_chunk_number automatically.
	pub fn get_next_chunk(
		&mut self, 
		deduplication_map: Option<&mut DeduplicationChunkMap>,
		) -> Result<Vec<u8>> {
		let mut chunk_header = ChunkHeader::new_empty(self.current_chunk_number);
		let chunk_size = self.object_header.chunk_size as usize;

		let mut buf = match self.file_type {
			FileType::Directory => {
				let mut cursor = Cursor::new(&self.encoded_directory_children);
				cursor.set_position(self.read_bytes_underlying_data);
				let (buf, read_bytes) = buffer_chunk(&mut cursor, chunk_size)?;
				self.read_bytes_underlying_data += read_bytes;
				buf

			},
			FileType::Symlink => {
				match &self.symlink_real_path {
					None => Vec::new(),
					Some(link_path) => {
						let mut cursor = Cursor::new(link_path.to_string_lossy().encode_directly());
						let (buf, read_bytes) = buffer_chunk(&mut cursor, chunk_size)?;
						self.read_bytes_underlying_data += read_bytes;
						self.symlink_real_path = None;
						buf
					},
				}
			},
			FileType::Hardlink => {
				match self.hard_link_filenumber {
					Some(filenumber) => {
						let mut cursor = Cursor::new(filenumber.encode_directly());
						let (buf, read_bytes) = buffer_chunk(&mut cursor, chunk_size)?;
						self.read_bytes_underlying_data += read_bytes;
						self.hard_link_filenumber = None;
						buf
					},
					None => Vec::new(),
				}		
			},
			FileType::File => {
				let (buf, read_bytes) = buffer_chunk(&mut self.underlying_file, chunk_size)?;
				self.read_bytes_underlying_data += read_bytes;
				buf
			},
			FileType::SpecialFile => {
				todo!()
				//TODO!
			}
		};
		if buf.is_empty() && self.read_bytes_underlying_data != 0 {
			//this case is the normal "file reader reached EOF".
			return Err(ZffError::new(ZffErrorKind::ReadEOF, ""));
		} else if buf.is_empty() && self.read_bytes_underlying_data == 0 {
			//this case ensures, that empty files will already get a chunk
			chunk_header.flags.empty_file = true;
			chunk_header.chunk_size = 0;
			chunk_header.crc32 = 0;
			let mut chunk = Vec::new();

			let mut encoded_header = if let Some(enc_header) = &self.object_header.encryption_header {
				let key = match enc_header.get_encryption_key_ref() {
					Some(key) => key,
					None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, self.current_chunk_number.to_string()))
				};
				chunk_header.encrypt_and_consume(key, enc_header.algorithm())?.encode_directly()
			} else {
				chunk_header.encode_directly()
			};

			chunk.append(&mut encoded_header);
			self.current_chunk_number += 1;
	   	 	return Err(ZffError::new(ZffErrorKind::EmptyFile(chunk), (self.current_chunk_number-1).to_string()))
		};

		self.update_hasher(&buf);
	    let crc32 = calculate_crc32(&buf);

	    // check same byte
	    if check_same_byte(&buf) {
	    	chunk_header.flags.same_bytes = true;
	    	buf = vec![buf[0]]
	    } else if let Some(deduplication_map) = deduplication_map {
	    	let b3h = blake3::hash(&buf);
	    	if let Ok(chunk_no) = deduplication_map.get_chunk_number(b3h) {
	    		buf = chunk_no.to_le_bytes().to_vec();
	    	} else {
	    		deduplication_map.append_entry(self.current_chunk_number, b3h)?;
	    	}
	    	chunk_header.flags.duplicate = true;
	    }

		let (compressed_data, inner_compression_flag) = compress_buffer(
			buf, 
			self.object_header.chunk_size as usize, 
			&self.object_header.compression_header)?;
		let compression_flag = inner_compression_flag;

		let mut chunk_data = match &self.encryption_information {
			Some(encryption_information) => {	
				Encryption::encrypt_chunk_content(
					&encryption_information.encryption_key,
					&compressed_data,
					chunk_header.chunk_number,
					&encryption_information.algorithm)?
			},
			None => compressed_data
		};

		let mut chunk = Vec::new();

	    // prepare chunk header:
		chunk_header.chunk_size = chunk_data.len() as u64; 
		chunk_header.crc32 = crc32;
		if compression_flag {
			chunk_header.flags.compression = true;
		}

		let mut encoded_header = if let Some(enc_header) = &self.object_header.encryption_header {
			let key = match enc_header.get_encryption_key_ref() {
				Some(key) => key,
				None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, self.current_chunk_number.to_string()))
			};
			chunk_header.encrypt_and_consume(key, enc_header.algorithm())?.encode_directly()
		} else {
			chunk_header.encode_directly()
		};

		chunk.append(&mut encoded_header);
		chunk.append(&mut chunk_data);
		self.current_chunk_number += 1;
	    Ok(chunk)
	}

	/// returns the appropriate encoded [FileFooter].
	/// A call of this method finalizes the underlying hashers. You should be care.
	pub fn get_encoded_footer(&mut self) -> Result<Vec<u8>> {
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
			self.file_header.file_number,
			self.acquisition_start,
			self.acquisition_end,
			hash_header,
			self.initial_chunk_number,
			self.current_chunk_number - self.initial_chunk_number,
			self.read_bytes_underlying_data,
			);
		if let Some(enc_info) = &self.encryption_information {
	    	footer.encrypt_directly(enc_info)
	    } else {
	    	Ok(footer.encode_directly())
	    }
	}
}

/*/// this implement Read for [FileEncoder]. This implementation should only used for a single zff segment file (e.g. in http streams).
/// State: completly untested.
impl Read for FileEncoder {
	fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
		let mut read_bytes = 0;
		//read encoded header, if there are remaining bytes to read.
        if let remaining_bytes @ 1.. = self.encoded_header_remaining_bytes {
            let mut inner_read_bytes = 0;
            let mut inner_cursor = Cursor::new(self.get_encoded_header());
            inner_cursor.seek(SeekFrom::End(-(remaining_bytes as i64)))?;
            inner_read_bytes += inner_cursor.read(&mut buf[read_bytes..])?;
            self.encoded_header_remaining_bytes -= inner_read_bytes;
            read_bytes += inner_read_bytes;
        }
        loop {
        	if read_bytes == buf.len() {
        		self.encoded_footer = match self.get_encoded_footer() {
        			Ok(footer) => footer,
        			Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        		};
        		self.encoded_footer_remaining_bytes = self.encoded_footer.len();
				break;
			};
        	match &self.current_chunked_data {
        		Some(data) => {
        			let mut inner_read_bytes = 0;
        			let mut inner_cursor = Cursor::new(&data);
        			inner_cursor.seek(SeekFrom::End(-(self.current_chunked_data_remaining_bytes as i64)))?;
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
        					e => return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
        				}
        			}
        		}
        	}
        }
        //read encoded footer, if there are remaining bytes to read.
        if let remaining_bytes @ 1.. = self.encoded_footer_remaining_bytes {
            let mut inner_read_bytes = 0;
            let mut inner_cursor = Cursor::new(&self.encoded_footer);
            inner_cursor.seek(SeekFrom::End(-(remaining_bytes as i64)))?;
            inner_read_bytes += inner_cursor.read(&mut buf[read_bytes..])?;
            self.encoded_footer_remaining_bytes -= inner_read_bytes;
            read_bytes += inner_read_bytes;
        }
        Ok(read_bytes)
	}
}*/