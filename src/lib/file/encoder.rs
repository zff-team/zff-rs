// - STD
use std::io::{Read, Cursor};
use std::path::PathBuf;

use std::collections::HashMap;
use std::time::SystemTime;

// - internal
use crate::{
	header::{FileHeader, HashHeader, ChunkHeader, HashValue, EncryptionInformation, ObjectHeader, DeduplicationChunkMap},
	footer::FileFooter,
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
};

#[cfg(feature = "log")]
use crate::hashes_to_log;

// - external
use digest::DynDigest;
use time::OffsetDateTime;

/// The [FileEncoder] can be used to encode a [crate::file::File].
pub struct FileEncoder {
	/// The appropriate [FileHeader].
	file_header: FileHeader,
	/// The appropriate [ObjectHeader].
	object_header: ObjectHeader,
	/// The underlying [File](std::fs::File) object to read from.
	underlying_file: Box<dyn Read>,
	/// optional encryption information, to encrypt the data with the given key and algorithm
	encryption_information: Option<EncryptionInformation>,
	/// HashMap for the Hasher objects to calculate the cryptographically hash values for this file. 
	hasher_map: HashMap<HashType, Box<dyn DynDigest>>,
	/// The first chunk number for this file.
	initial_chunk_number: u64,
	/// The current chunk number
	current_chunk_number: u64,
	/// The number of bytes, which were read from the underlying file.
	read_bytes_underlying_data: u64,
	acquisition_start: u64,
	acquisition_end: u64,
	filetype_encoding_information: FileTypeEncodingInformation,
}

/// This enum contains the information, which are needed to encode the different file types.
pub enum FileTypeEncodingInformation {
	/// A regular file.
	File,
	/// A directory with the given children.
	Directory(Vec<u64>), // directory children,
	/// A symlink with the given real path.
	Symlink(PathBuf), // symlink real path
	/// A hardlink with the given twin filenumber.
	Hardlink(u64), // hardlink filenumber
	/// A special file with the given special file information.
	#[cfg(target_family = "unix")]
	SpecialFile(SpecialFileEncodingInformation), // special file information (rdev, type_flag)
}

/// This enum contains the information, which are needed to encode the different special file types.
#[cfg(target_family = "unix")]
pub enum SpecialFileEncodingInformation {
	/// A fifo file with the given rdev-id.
	Fifo(u64), // fifo(rdev),
	/// A char file with the given rdev-id.
	Char(u64), // char(rdev),
	/// A block file with the given rdev-id.
	Block(u64), // block(rdev),
	/// A socket file with the given rdev-id.
	Socket(u64), // socket(rdev),
}

impl FileEncoder {
	/// creates a new [FileEncoder] with the given values.
	pub fn new(
		file_header: FileHeader,
		object_header: ObjectHeader,
		file: Box<dyn Read>,
		hash_types: Vec<HashType>,
		encryption_information: Option<EncryptionInformation>,
		current_chunk_number: u64,
		filetype_encoding_information: FileTypeEncodingInformation) -> Result<FileEncoder> {
		
		let mut hasher_map = HashMap::new();
	    for h_type in hash_types {
	        let hasher = Hash::new_hasher(&h_type);
	        hasher_map.insert(h_type.clone(), hasher);
	    };
		Ok(Self {
			file_header,
			object_header,
			underlying_file: Box::new(file),
			hasher_map,
			encryption_information,
			initial_chunk_number: current_chunk_number,
			current_chunk_number,
			read_bytes_underlying_data: 0,
			acquisition_start: 0,
			acquisition_end: 0,
			filetype_encoding_information,
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
		let mut eof = false;

		let mut buf = match &self.filetype_encoding_information {
			FileTypeEncodingInformation::Directory(directory_children) => {
				let encoded_directory_children = if directory_children.is_empty() {
					Vec::new()
				} else {
					directory_children.encode_directly()
				};
				let mut cursor = Cursor::new(&encoded_directory_children);
				cursor.set_position(self.read_bytes_underlying_data);
				let (buf, read_bytes) = buffer_chunk(&mut cursor, chunk_size)?;
				self.read_bytes_underlying_data += read_bytes;
				buf

			},
			FileTypeEncodingInformation::Symlink(symlink_real_path) => {
				let encoded_symlink_real_path = symlink_real_path.to_string_lossy().encode_directly();
				let mut cursor = Cursor::new(&encoded_symlink_real_path);
				cursor.set_position(self.read_bytes_underlying_data);
				let (buf, read_bytes) = buffer_chunk(&mut cursor, chunk_size)?;
				self.read_bytes_underlying_data += read_bytes;
				if read_bytes > 0 {
					buf
				} else {
					eof = true;
					Vec::new()
				}
			},
			FileTypeEncodingInformation::Hardlink(hardlink_filenumber) => {
				let encoded_hardlink_filenumber = hardlink_filenumber.encode_directly();
				let mut cursor = Cursor::new(&encoded_hardlink_filenumber);
				cursor.set_position(self.read_bytes_underlying_data);
				let (buf, read_bytes) = buffer_chunk(&mut cursor, chunk_size)?;
				self.read_bytes_underlying_data += read_bytes;
				if read_bytes > 0 {
					buf
				} else {
					eof = true;
					Vec::new()
				}	
			},
			FileTypeEncodingInformation::File => {
				let (buf, read_bytes) = buffer_chunk(&mut self.underlying_file, chunk_size)?;
				self.read_bytes_underlying_data += read_bytes;
				buf
			},
			// contains the rdev-id and a flag for the type of the special file 
			// (0 if fifo-, 1 if char-, 2 if block-, and 3 if it is a socket-file).
			#[cfg(target_family = "unix")]
			FileTypeEncodingInformation::SpecialFile(specialfile_encoding_information) => {
				let (rdev_id, type_flag) = match specialfile_encoding_information {
					SpecialFileEncodingInformation::Fifo(rdev_id) => (rdev_id, 0_u8),
					SpecialFileEncodingInformation::Char(rdev_id) => (rdev_id, 1),
					SpecialFileEncodingInformation::Block(rdev_id) => (rdev_id, 2),
					SpecialFileEncodingInformation::Socket(rdev_id) => (rdev_id, 3),
				};
				let mut encoded_data = rdev_id.encode_directly();
				encoded_data.append(&mut type_flag.encode_directly());
				let mut cursor = Cursor::new(&encoded_data);
				cursor.set_position(self.read_bytes_underlying_data);
				let (buf, read_bytes) = buffer_chunk(&mut cursor, chunk_size)?;
				self.read_bytes_underlying_data += read_bytes;
				if read_bytes > 0 {
					buf
				} else {
					eof = true;
					Vec::new()
				}
			}
		};
		if buf.is_empty() && self.read_bytes_underlying_data != 0 || eof {
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
				chunk_header.encrypt_and_consume(key, &enc_header.algorithm)?.encode_directly()
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
	    // if the length of the buffer is not equal the target chunk size, 
	    // the condition failed and same byte flag can not be set.
	    if buf.len() == chunk_size && check_same_byte(&buf) {
	    	chunk_header.flags.same_bytes = true;
	    	buf = vec![buf[0]]
	    } else if let Some(deduplication_map) = deduplication_map {
	    	let b3h = blake3::hash(&buf);
	    	if let Ok(chunk_no) = deduplication_map.get_chunk_number(b3h) {
	    		buf = chunk_no.to_le_bytes().to_vec();
	    		chunk_header.flags.duplicate = true;
	    	} else {
	    		deduplication_map.append_entry(self.current_chunk_number, b3h)?;
	    	}
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
			chunk_header.encrypt_and_consume(key, &enc_header.algorithm)?.encode_directly()
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
			let mut hash_value = HashValue::new_empty(hash_type);
			hash_value.set_hash(hash.to_vec());
			hash_values.push(hash_value);
		}

		#[cfg(feature = "log")]
		hashes_to_log(self.object_header.object_number, Some(self.file_header.file_number), &hash_values);

		let hash_header = HashHeader::new(hash_values);
		let footer = FileFooter::new(
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