// - STD
use std::io::{Read, Cursor};
use std::path::PathBuf;
use std::fs::File;
use std::collections::HashMap;
use std::time::SystemTime;
#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_family = "unix")]
use std::os::unix::fs::FileTypeExt;

#[cfg(target_family = "unix")]
use crate::SpecialFileEncodingInformation;
// - internal
use crate::{
	Result,
	io::{buffer_chunk, calculate_crc32, compress_buffer},
	HeaderCoding,
	HashType,
	Hash,
	Signature,
	ZffError,
	ZffErrorKind,
	Encryption,
	FileTypeEncodingInformation,
	DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_PHYSICAL,
	DEFAULT_HEADER_VERSION_HASH_VALUE_HEADER,
	DEFAULT_HEADER_VERSION_HASH_HEADER,
	DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_LOGICAL,
};

#[cfg(feature = "log")]
use crate::hashes_to_log;

use crate::{
	header::{
		ObjectHeader, 
		HashHeader, 
		ChunkHeader, 
		HashValue, 
		FileHeader,
		FileType,
		EncryptionInformation,
		DeduplicationChunkMap,
	},
	footer::{ObjectFooterPhysical, ObjectFooterLogical},
	FileEncoder,
	io::check_same_byte,
};

// - external
use digest::DynDigest;
use ed25519_dalek::SigningKey;
use time::OffsetDateTime;

/// An encoder for each object. This is a wrapper Enum for [PhysicalObjectEncoder] and [LogicalObjectEncoder].
pub enum ObjectEncoder<R: Read> {
	/// Wrapper for [PhysicalObjectEncoder].
	Physical(Box<PhysicalObjectEncoder<R>>),
	/// Wrapper for [LogicalObjectEncoder].
	Logical(Box<LogicalObjectEncoder>),
}

impl<R: Read> ObjectEncoder<R> {
	/// returns the appropriate object number.
	pub fn obj_number(&self) -> u64 {
		match self {
			ObjectEncoder::Physical(obj) => obj.obj_number(),
			ObjectEncoder::Logical(obj) => obj.obj_number(),
		}
	}

	/// returns the current chunk number.
	pub fn current_chunk_number(&self) -> u64 {
		match self {
			ObjectEncoder::Physical(obj) => obj.current_chunk_number,
			ObjectEncoder::Logical(obj) => obj.current_chunk_number,
		}
	}

	/// returns a reference of the appropriate [ObjectHeader].
	pub fn get_obj_header(&mut self) -> &ObjectHeader {
		match self {
			ObjectEncoder::Physical(obj) => &obj.obj_header,
			ObjectEncoder::Logical(obj) => &obj.obj_header,
		}
	}

	/// returns the appropriate encoded [ObjectHeader].
	pub fn get_encoded_header(&mut self) -> Vec<u8> {
		match self {
			ObjectEncoder::Physical(obj) => obj.get_encoded_header(),
			ObjectEncoder::Logical(obj) => obj.get_encoded_header(),
		}
	}

	/// returns the underlying encryption key (if available).
	pub fn encryption_key(&self) -> Option<Vec<u8>> {
		match self {
			ObjectEncoder::Physical(obj) => obj.encryption_key.clone(),
			ObjectEncoder::Logical(obj) => obj.encryption_key.clone(),
		}
	}

	/// returns the appropriate object footer.
	pub fn get_encoded_footer(&mut self) -> Result<Vec<u8>> {
		match self {
			ObjectEncoder::Physical(obj) => obj.get_encoded_footer(),
			ObjectEncoder::Logical(obj) => obj.get_encoded_footer(),
		}
	}

	/// returns the next data.
	pub fn get_next_data(
		&mut self, 
		current_offset: u64, 
		current_segment_no: u64, 
		deduplication_map: Option<&mut DeduplicationChunkMap>
		) -> Result<Vec<u8>> {
		match self {
			ObjectEncoder::Physical(obj) => obj.get_next_chunk(deduplication_map),
			ObjectEncoder::Logical(obj) => obj.get_next_data(current_offset, current_segment_no, deduplication_map),
		}
	}
}

/// The [PhysicalObjectEncoder] can be used to encode a physical object.
pub struct PhysicalObjectEncoder<R: Read> {
	/// The appropriate object header
	obj_header: ObjectHeader,
	underlying_data: R,
	read_bytes_underlying_data: u64,
	current_chunk_number: u64,
	initial_chunk_number: u64,
	hasher_map: HashMap<HashType, Box<dyn DynDigest>>,
	signing_key: Option<SigningKey>,
	has_hash_signatures: bool,
	encryption_key: Option<Vec<u8>>,
	acquisition_start: u64,
	acquisition_end: u64,
}

impl<R: Read> PhysicalObjectEncoder<R> {
	/// Returns a new [PhysicalObjectEncoder] by the given values.
	pub fn new(
		obj_header: ObjectHeader,
		reader: R,
		hash_types: Vec<HashType>,
		signing_key_bytes: Option<Vec<u8>>,
		current_chunk_number: u64) -> Result<PhysicalObjectEncoder<R>> {
		
		let signing_key = match &signing_key_bytes {
	    	Some(bytes) => Some(Signature::bytes_to_signingkey(bytes)?),
	    	None => None
	    };

		let (_, encryption_key) = if let Some(encryption_header) = &obj_header.encryption_header {
			match encryption_header.get_encryption_key() {
				Some(key) => (obj_header.encode_encrypted_header_directly(&key)?, Some(key)),
				None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, obj_header.object_number.to_string()))
			}
	    } else {
	    	(obj_header.encode_directly(), None)
	    };

		let mut hasher_map = HashMap::new();
	    for h_type in hash_types {
	        let hasher = Hash::new_hasher(&h_type);
	        hasher_map.insert(h_type.clone(), hasher);
	    };
		Ok(Self {
			has_hash_signatures: obj_header.has_hash_signatures(),
			obj_header,
			underlying_data: reader,
			read_bytes_underlying_data: 0,
			current_chunk_number,
			initial_chunk_number: current_chunk_number,
			hasher_map,
			encryption_key,
			signing_key,
			acquisition_start: 0,
			acquisition_end: 0,
		})
	}

	/// Returns the current chunk number.
	pub fn object_header(&self) -> &ObjectHeader {
		&self.obj_header
	}

	fn update_hasher(&mut self, buffer: &[u8]) {
		for hasher in self.hasher_map.values_mut() {
			hasher.update(buffer);
		}
	}

	/// Returns the current chunk number.
	pub fn current_chunk_number(&self) -> u64 {
		self.current_chunk_number
	}

	/// Returns the encoded object header.
	/// Note: **A call of this method sets the acquisition start time to the current time**.
	pub fn get_encoded_header(&mut self) -> Vec<u8> {
		if self.acquisition_start == 0 {
			self.acquisition_start = OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64;
		}
		if let Some(encryption_key) = &self.encryption_key {
			//unwrap should be safe here, because we have already testet this before.
	    	self.obj_header.encode_encrypted_header_directly(encryption_key).unwrap()
	    } else {
	    	self.obj_header.encode_directly()
	    }
	}


	/// Returns the encoded Chunk - this method will increment the self.current_chunk_number automatically.
	pub fn get_next_chunk(
		&mut self,
		deduplication_map: Option<&mut DeduplicationChunkMap>,
		) -> Result<Vec<u8>> {
		let mut chunk = Vec::new();

		// prepare chunked data:
	    let chunk_size = self.obj_header.chunk_size as usize;
	    let (mut buf, read_bytes) = buffer_chunk(&mut self.underlying_data, chunk_size)?;
	    self.read_bytes_underlying_data += read_bytes;
	    if buf.is_empty() {
	    	return Err(ZffError::new(ZffErrorKind::ReadEOF, ""));
	    };
	    self.update_hasher(&buf);
	    let crc32 = calculate_crc32(&buf);

	    // create chunk header
	    let mut chunk_header = ChunkHeader::new_empty(self.current_chunk_number);

	    // check same byte (but only if length of the buf is == chunk size)
	    if read_bytes == chunk_size as u64 && check_same_byte(&buf) {
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

	    let (chunked_data, compression_flag) = compress_buffer(buf, self.obj_header.chunk_size as usize, &self.obj_header.compression_header)?;

	    // prepare chunk header:
	    chunk_header.crc32 = crc32;
	    if compression_flag {
			chunk_header.flags.compression = true;
		}
		let mut chunked_data = match &self.encryption_key {
			Some(encryption_key) => {
				let encryption_algorithm = match &self.obj_header.encryption_header {
					Some(header) => header.algorithm(),
					None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionHeader, "")),
				};
				
				Encryption::encrypt_chunk_content(
					encryption_key,
					&chunked_data,
					chunk_header.chunk_number,
					encryption_algorithm)?
			},
			None => chunked_data,
		};
		
		chunk_header.chunk_size = chunked_data.len() as u64;

		let mut encoded_header = if let Some(enc_header) = &self.obj_header.encryption_header {
			let key = match enc_header.get_encryption_key_ref() {
				Some(key) => key,
				None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, self.current_chunk_number.to_string()))
			};
			chunk_header.encrypt_and_consume(key, enc_header.algorithm())?.encode_directly()
		} else {
			chunk_header.encode_directly()
		};

		chunk.append(&mut encoded_header);
		chunk.append(&mut chunked_data);
		self.current_chunk_number += 1;
	    Ok(chunk)
	}

	/// Generates a appropriate footer. Attention: A call of this method ...
	/// - sets the acquisition end time to the current time
	/// - finalizes the underlying hashers
	pub fn get_encoded_footer(&mut self) -> Result<Vec<u8>> {
		self.acquisition_end = OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64;
		let mut hash_values = Vec::new();
	    for (hash_type, hasher) in self.hasher_map.clone() {
	        let hash = hasher.finalize();
	        let mut hash_value = HashValue::new_empty(DEFAULT_HEADER_VERSION_HASH_VALUE_HEADER, hash_type);
	        hash_value.set_hash(hash.to_vec());
	        if self.has_hash_signatures {
	        	if let Some(signing_key) = &self.signing_key {
	        		let signature = Signature::sign(signing_key, &hash);
	        		hash_value.set_ed25519_signature(signature);
	        	}
	        };
	        hash_values.push(hash_value);
	    }

	    #[cfg(feature = "log")]
		hashes_to_log(self.obj_header.object_number, None, &hash_values);

	    let hash_header = HashHeader::new(DEFAULT_HEADER_VERSION_HASH_HEADER, hash_values);
		let footer = ObjectFooterPhysical::new(
			DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_PHYSICAL,
			self.obj_number(),
			self.acquisition_start,
			self.acquisition_end,
			self.read_bytes_underlying_data,
			self.initial_chunk_number,
			self.current_chunk_number - self.initial_chunk_number,
			hash_header);

		if let Some(encryption_key) = &self.encryption_key {
			let encryption_information = EncryptionInformation {
				encryption_key: encryption_key.to_vec(),
				// unwrap should be safe here: there should not an encryption key exists without an encryption header.
				algorithm: self.obj_header.encryption_header.clone().unwrap().algorithm().clone()
			};
	    	footer.encrypt_directly(encryption_information)
	    } else {
	    	Ok(footer.encode_directly())
	    }
	}

	/// Returns the appropriate object number.
	pub fn obj_number(&self) -> u64 {
		self.obj_header.object_number
	}

	/// Returns the underlying encryption key (if available).
	pub fn encryption_key(&self) -> Option<Vec<u8>> {
		self.encryption_key.clone()
	}
}

/// The [LogicalObjectEncoder] can be used to encode a logical object.
pub struct LogicalObjectEncoder {
	/// The appropriate original object header
	obj_header: ObjectHeader,
	//encoded_header_remaining_bytes: usize,
	files: Vec<(PathBuf, FileHeader)>,
	current_file_encoder: Option<FileEncoder>,
	current_file_header_read: bool,
	current_file_number: u64,
	hash_types: Vec<HashType>,
	encryption_key: Option<Vec<u8>>,
	signing_key_bytes: Option<Vec<u8>>,
	current_chunk_number: u64,
	symlink_real_paths: HashMap<u64, PathBuf>,
	hardlink_map: HashMap<u64, u64>, //<filenumber, filenumber of hardlink>
	directory_children: HashMap<u64, Vec<u64>>, //<directory file number, Vec<child filenumber>>
	object_footer: ObjectFooterLogical,
	empty_file_eof: bool,
}

impl LogicalObjectEncoder {
	/// Returns the encoded footer for this object.
	/// Sets the acquisition end timestamp of the object footer to current system time.
	pub fn get_encoded_footer(&mut self) -> Result<Vec<u8>> {
		let systemtime = OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64;
		self.object_footer.set_acquisition_end(systemtime);
		if let Some(encryption_key) = &self.encryption_key {
			let encryption_information = EncryptionInformation {
				encryption_key: encryption_key.to_vec(),
				// unwrap should be safe here: there should not an encryption key exists without an encryption header.
				algorithm: self.obj_header.encryption_header.clone().unwrap().algorithm().clone()
			};
	    	self.object_footer.encrypt_directly(encryption_information)
	    } else {
	    	Ok(self.object_footer.encode_directly())
	    }
	}

	/// Returns the current chunk number.
	pub fn object_header(&self) -> &ObjectHeader {
		&self.obj_header
	}

	/// Returns a new [LogicalObjectEncoder] by the given values.
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		obj_header: ObjectHeader,
		files: Vec<(PathBuf, FileHeader)>,
		root_dir_filenumbers: Vec<u64>,
		hash_types: Vec<HashType>,
		signing_key_bytes: Option<Vec<u8>>,
		symlink_real_paths: HashMap<u64, PathBuf>, //File number <-> Symlink real path
		hardlink_map: HashMap<u64, u64>, // <filenumber, filenumber of hardlink>
		directory_children: HashMap<u64, Vec<u64>>,
		current_chunk_number: u64) -> Result<LogicalObjectEncoder> {		

		// ensures that the encryption key is available in decrypted form.
		let (_encoded_header, encryption_key) = if let Some(encryption_header) = &obj_header.encryption_header {
			match encryption_header.get_encryption_key() {
				Some(key) => (obj_header.encode_encrypted_header_directly(&key)?, Some(key)),
				None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, obj_header.object_number.to_string()))
			}
	    } else {
	    	(obj_header.encode_directly(), None)
	    };

		let mut files = files;
		let (path, current_file_header) = match files.pop() {
			Some((path, header)) => (path, header),
			None => return Err(ZffError::new(ZffErrorKind::NoFilesLeft, "There is no input file"))
		};
		//open first file path - if the path is not accessable, create an empty reader.
		#[cfg_attr(target_os = "windows", allow(clippy::needless_borrows_for_generic_args))]
		let reader = match File::open(&path) {
			Ok(reader) => Box::new(reader),
			Err(_) => create_empty_reader()
		};

		let current_file_number = current_file_header.file_number;

		let encryption_information = if let Some(encryption_key) = &encryption_key {
			obj_header.encryption_header.clone().map(|enc_header| EncryptionInformation::new(encryption_key.to_vec(), enc_header.algorithm().clone()))
		} else {
			None
		};

		let filetype_encoding_information = match current_file_header.file_type {
			FileType::File => FileTypeEncodingInformation::File,
			FileType::Directory => {
				let mut children = Vec::new();
				for child in directory_children.get(&current_file_number).unwrap_or(&Vec::new()) {
					children.push(*child);
				};
				FileTypeEncodingInformation::Directory(children)
			},
			FileType::Symlink => {
				let real_path = symlink_real_paths.get(&current_file_number).unwrap_or(&PathBuf::new()).clone();
				FileTypeEncodingInformation::Symlink(real_path)
			},
			FileType::Hardlink => {
				let hardlink_filenumber = hardlink_map.get(&current_file_number).unwrap_or(&0);
				FileTypeEncodingInformation::Hardlink(*hardlink_filenumber)
			},
			#[cfg(target_family = "windows")]
			FileType::SpecialFile => unreachable!("Special files are not supported on Windows"),
			#[cfg(target_family = "unix")]
			FileType::SpecialFile => {
				let metadata = std::fs::metadata(&path)?;

				let specialfile_info = if metadata.file_type().is_char_device() {
					SpecialFileEncodingInformation::Char(metadata.rdev())
				} else if metadata.file_type().is_block_device() {
					SpecialFileEncodingInformation::Block(metadata.rdev())
				} else if metadata.file_type().is_fifo() {
					SpecialFileEncodingInformation::Fifo(metadata.rdev())
				} else if metadata.file_type().is_socket() {
					SpecialFileEncodingInformation::Socket(metadata.rdev())
				} else {
					return Err(ZffError::new(ZffErrorKind::UnknownFileType, "Unknown special file type"));
				};
				FileTypeEncodingInformation::SpecialFile(specialfile_info)
			},
		};

		let first_file_encoder = Some(FileEncoder::new(
			current_file_header,
			obj_header.clone(),
			Box::new(reader), 
			hash_types.clone(), 
			encryption_information, 
			current_chunk_number, 
			filetype_encoding_information)?);
		
		let mut object_footer = ObjectFooterLogical::new_empty(DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_LOGICAL, obj_header.object_number);
		for filenumber in root_dir_filenumbers {
			object_footer.add_root_dir_filenumber(filenumber)
		};

		Ok(Self {
			obj_header,
			files,
			current_file_encoder: first_file_encoder,
			current_file_header_read: false,
			current_file_number,
			hash_types,
			encryption_key,
			signing_key_bytes,
			current_chunk_number,
			symlink_real_paths,
			hardlink_map,
			directory_children,
			object_footer,
			empty_file_eof: false,
		})
	}

	/// Returns the appropriate object number.
	pub fn obj_number(&self) -> u64 {
		self.obj_header.object_number
	}

	/// Returns the current chunk number
	pub fn current_chunk_number(&self) -> u64 {
		self.current_chunk_number
	}

	/// Returns the current signature key (if available).
	pub fn signing_key(&self) -> Option<SigningKey> {
	    match &self.signing_key_bytes {
	    	Some(bytes) => Signature::bytes_to_signingkey(bytes).ok(),
	    	None => None
	    }
	}

	/// Returns the encoded object header.
	pub fn get_encoded_header(&mut self) -> Vec<u8> {
		if let Some(encryption_key) = &self.encryption_key {
			//unwrap should be safe here, because we have already testet this before.
	    	self.obj_header.encode_encrypted_header_directly(encryption_key).unwrap()
	    } else {
	    	self.obj_header.encode_directly()
	    }
	}

	/// Returns the next encoded data - an encoded [FileHeader], an encoded file chunk or an encoded [FileFooter].
	/// This method will increment the self.current_chunk_number automatically.
	pub fn get_next_data(
		&mut self, 
		current_offset: u64, 
		current_segment_no: u64,
		deduplication_map: Option<&mut DeduplicationChunkMap>) -> Result<Vec<u8>> {
		match self.current_file_encoder {
			Some(ref mut file_encoder) => {
				// return file header
				if !self.current_file_header_read {
					self.current_file_header_read = true;
					if self.object_footer.acquisition_start == 0 {
						self.object_footer.set_acquisition_start(OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64);
					}
					self.object_footer.add_file_header_segment_number(self.current_file_number, current_segment_no);
					self.object_footer.add_file_header_offset(self.current_file_number, current_offset);
					return Ok(file_encoder.get_encoded_header());
				}
				
				let mut data = Vec::new();
				// return next chunk
				if !self.empty_file_eof {
					match file_encoder.get_next_chunk(deduplication_map) {
						Ok(data) => {
							self.current_chunk_number += 1;
							return Ok(data);
						},
						Err(e) => match e.get_kind() {
							ZffErrorKind::EmptyFile(empty_file_data) => {
								// increment the current chunk number as we write a empty chunk as placeholder
								self.current_chunk_number += 1;
								// append "empty" placeholder chunk (header) to the bytes which will be returned
								data.append(&mut empty_file_data.clone());
								// re-calculate the "current_offset" (append the bytes from the placeholder chunk)
								//current_offset += data.len() as u64;
								self.empty_file_eof = true;
								return Ok(data);
							},
							ZffErrorKind::ReadEOF => (),
							ZffErrorKind::NotAvailableForFileType => (),
							_ => return Err(e)
						}
					};
				} else {
					self.empty_file_eof = false;
				};
	

				//return file footer, set next file_encoder
				data.append(&mut file_encoder.get_encoded_footer()?);

				self.object_footer.add_file_footer_segment_number(self.current_file_number, current_segment_no);
				self.object_footer.add_file_footer_offset(self.current_file_number, current_offset);
				
				let (path, current_file_header) = match self.files.pop() {
					Some((path, header)) => (path, header),
					None => {
						// if no files left, the acquisition ends and the date will be written to the object footer.
						// The appropriate file footer will be returned.
						self.object_footer.set_acquisition_end(OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64);
						self.current_file_encoder = None;
						return Ok(data);
					}
				};

				#[cfg_attr(target_os = "windows", allow(clippy::needless_borrows_for_generic_args))]
				let reader = match File::open(&path) {
					Ok(reader) => Box::new(reader),
					Err(_) => create_empty_reader()
				};
		     	
				self.current_file_number = current_file_header.file_number;

				let encryption_information = if let Some(encryption_key) = &self.encryption_key {
					self.obj_header.encryption_header.as_ref().map(|enc_header| EncryptionInformation::new(encryption_key.to_vec(), enc_header.algorithm().clone()))
				} else {
					None
				};

				let filetype_encoding_information = match current_file_header.file_type {
					FileType::File => FileTypeEncodingInformation::File,
					FileType::Directory => {
						let mut children = Vec::new();
						for child in self.directory_children.get(&self.current_file_number).unwrap_or(&Vec::new()) {
							children.push(*child);
						};
						FileTypeEncodingInformation::Directory(children)
					},
					FileType::Symlink => {
						let real_path = self.symlink_real_paths.get(&self.current_file_number).unwrap_or(&PathBuf::new()).clone();
						FileTypeEncodingInformation::Symlink(real_path)
					},
					FileType::Hardlink => {
						let hardlink_filenumber = self.hardlink_map.get(&self.current_file_number).unwrap_or(&0);
						FileTypeEncodingInformation::Hardlink(*hardlink_filenumber)
					},
					#[cfg(target_family = "windows")]
					FileType::SpecialFile => unreachable!("Special files are not supported on Windows"),
					#[cfg(target_family = "unix")]
					FileType::SpecialFile => {
						let metadata = std::fs::metadata(&path)?;
		
						let specialfile_info = if metadata.file_type().is_char_device() {
							SpecialFileEncodingInformation::Char(metadata.rdev())
						} else if metadata.file_type().is_block_device() {
							SpecialFileEncodingInformation::Block(metadata.rdev())
						} else if metadata.file_type().is_fifo() {
							SpecialFileEncodingInformation::Fifo(metadata.rdev())
						} else if metadata.file_type().is_socket() {
							SpecialFileEncodingInformation::Socket(metadata.rdev())
						} else {
							return Err(ZffError::new(ZffErrorKind::UnknownFileType, "Unknown special file type"));
						};
						FileTypeEncodingInformation::SpecialFile(specialfile_info)
					},
				};
       			
			    self.current_file_header_read = false;
				self.current_file_encoder = Some(FileEncoder::new(
					current_file_header, 
					self.obj_header.clone(),
					reader, 
					self.hash_types.clone(), 
					encryption_information, 
					self.current_chunk_number, 
					filetype_encoding_information)?);
				Ok(data)
			},
			None => {
				self.object_footer.set_acquisition_end(OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64);
				Err(ZffError::new(ZffErrorKind::ReadEOF, ""))
			},
		}	
	}

	/// Returns the underlying encryption key (if available).
	pub fn encryption_key(&self) -> Option<Vec<u8>> {
		self.encryption_key.clone()
	}

}

fn create_empty_reader() -> Box<dyn Read> {
	let buffer = Vec::<u8>::new();
	let cursor = Cursor::new(buffer);
	Box::new(cursor)
}