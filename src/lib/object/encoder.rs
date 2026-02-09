// - Parent
use super::*;


#[cfg(feature = "log")]
use crate::hashes_to_log;

use crate::{
	header::{
		ObjectHeader, 
		HashHeader,
		HashValue,
		EncryptionInformation,
		DeduplicationMetadata,
	},
	footer::{ObjectFooterPhysical, ObjectFooterLogical},
	FileEncoder,
};
use super::chunking;

// - external
use ed25519_dalek::SigningKey;
use time::OffsetDateTime;

/// Returns the current state of encoding.
#[derive(Debug, Clone, Default)]
pub(crate) enum EncodingState {
	/// Returns a prepared chunk.
	PreparedChunk(PreparedChunk),
	/// returns prepared data (contains a prepared chunk, a file header or a file footer).
	PreparedData(PreparedData),
	/// is used, if the source reader reaches a EOF state.
	#[default]
	ReadEOF,
}

/// Contains a prepared data object. This can be a [PreparedChunk], a [PreparedFileHeader] or a [PreparedFileFooter].
#[derive(Debug, Clone)]
pub(crate) enum PreparedData {
	/// A prepared chunk.
	PreparedChunk(PreparedChunk),
	/// A prepared file header.
	PreparedFileHeader(Vec<u8>),
	/// A prepared file footer.
	PreparedFileFooter(Vec<u8>),
}

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
	pub fn get_obj_header(&self) -> &ObjectHeader {
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
	pub(crate) fn get_next_data<D: Read + Seek>(
		&mut self, 
		current_offset: u64, 
		current_segment_no: u64, 
		deduplication_metadata: Option<&mut DeduplicationMetadata<D>>
		) -> Result<EncodingState> {
		match self {
			ObjectEncoder::Physical(obj) => obj.get_next_chunk(deduplication_metadata),
			ObjectEncoder::Logical(obj) => obj.get_next_data(current_offset, current_segment_no, deduplication_metadata),
		}
	}

	/// Returns the total number of files left in the object encoder.
	/// Will return None if the object encoder is not a logical object encoder.
	pub fn files_left(&self) -> Option<u64> {
		match self {
			ObjectEncoder::Physical(_) => None,
			ObjectEncoder::Logical(obj) => Some(obj.logical_object_source.remaining_elements()),
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
	encoding_thread_pool_manager: EncodingThreadPoolManager,
	signing_key: Option<SigningKey>,
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
				None => return Err(ZffError::new(
					ZffErrorKind::EncryptionError, ERROR_MISSING_ENCRYPTION_HEADER_KEY))
			}
	    } else {
	    	(obj_header.encode_directly(), None)
	    };

		let mut encoding_thread_pool_manager = EncodingThreadPoolManager::new(
			obj_header.compression_header.clone(), obj_header.chunk_size as usize);

	    for h_type in hash_types {
			encoding_thread_pool_manager.add_hashing_thread(h_type.clone());
	    };
		
		Ok(Self {
			obj_header,
			underlying_data: reader,
			read_bytes_underlying_data: 0,
			current_chunk_number,
			initial_chunk_number: current_chunk_number,
			encoding_thread_pool_manager,
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
	pub(crate) fn get_next_chunk<D: Read + Seek>(
		&mut self,
		deduplication_metadata: Option<&mut DeduplicationMetadata<D>>,
		) -> Result<EncodingState> {
			
		// checks and adds a deduplication thread to the internal thread manager (check is included in the add_deduplication_thread method)
		if deduplication_metadata.is_some() {
			self.encoding_thread_pool_manager.hashing_threads.add_deduplication_thread();
		};

		// prepare chunked data:
	    let chunk_size = self.obj_header.chunk_size as usize;
	    let buffered_chunk = buffer_chunk(&mut self.underlying_data, chunk_size)?;
	    self.read_bytes_underlying_data += buffered_chunk.bytes_read;
	    if buffered_chunk.buffer.is_empty() {
	    	return Ok(EncodingState::ReadEOF);
	    };

		self.encoding_thread_pool_manager.update(buffered_chunk.buffer);

		let encryption_algorithm = self.obj_header.encryption_header.as_ref().map(|encryption_header| &encryption_header.algorithm);
		let encryption_key = if let Some(encryption_header) = &self.obj_header.encryption_header {
			match encryption_header.get_encryption_key_ref() {
				Some(key) => Some(key),
				None => return Err(ZffError::new(
					ZffErrorKind::EncryptionError, 
					ERROR_MISSING_ENCRYPTION_HEADER_KEY))
			}
	    } else {
	    	None
	    };

		let chunk = chunking(
			&mut self.encoding_thread_pool_manager,
			self.current_chunk_number,
			buffered_chunk.bytes_read,
			chunk_size as u64,
			deduplication_metadata,
			encryption_key,
			encryption_algorithm)?;
	    
		self.current_chunk_number += 1;
	    Ok(EncodingState::PreparedData(PreparedData::PreparedChunk(chunk)))
	}

	/// Generates a appropriate footer. Attention: A call of this method ...
	/// - sets the acquisition end time to the current time
	/// - finalizes the underlying hashing threads
	pub fn get_encoded_footer(&mut self) -> Result<Vec<u8>> {
		self.acquisition_end = OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64;
		let mut hash_values = Vec::new();
	    for (hash_type, hash) in self.encoding_thread_pool_manager.hashing_threads.finalize_all() {
	        let mut hash_value = HashValue::new_empty(hash_type.clone());
	        hash_value.set_hash(hash.to_vec());
			if let Some(signing_key) = &self.signing_key {
				let signature = Signature::sign(signing_key, &hash);
				hash_value.set_ed25519_signature(signature);
			}
	        hash_values.push(hash_value);
	    }

	    #[cfg(feature = "log")]
		hashes_to_log(self.obj_header.object_number, None, &hash_values);

	    let hash_header = HashHeader::new(hash_values);
		let footer = ObjectFooterPhysical::new(
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
				algorithm: self.obj_header.encryption_header.clone().unwrap().algorithm.clone()
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
	logical_object_source: Box<dyn LogicalObjectSource>,
	current_file_encoder: Option<FileEncoder>,
	current_file_header_read: bool,
	current_file_number: u64,
	encoding_thread_pool_manager: Rc<RefCell<EncodingThreadPoolManager>>,
	encryption_key: Option<Vec<u8>>,
	signing_key: Option<SigningKey>,
	current_chunk_number: u64,
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
				algorithm: self.obj_header.encryption_header.clone().unwrap().algorithm.clone()
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
	pub fn new(
		obj_header: ObjectHeader,
		mut logical_object_source: Box<dyn LogicalObjectSource>,
		hash_types: Vec<HashType>,
		signing_key_bytes: Option<Vec<u8>>,
		current_chunk_number: u64) -> Result<LogicalObjectEncoder> {		

		// ensures that the encryption key is available in decrypted form.
		let (_encoded_header, encryption_key) = if let Some(encryption_header) = &obj_header.encryption_header {
			match encryption_header.get_encryption_key() {
				Some(key) => (obj_header.encode_encrypted_header_directly(&key)?, Some(key)),
				None => return Err(ZffError::new(
					ZffErrorKind::EncryptionError, 
					ERROR_MISSING_ENCRYPTION_HEADER_KEY))
			}
	    } else {
	    	(obj_header.encode_directly(), None)
	    };

		let signing_key = match &signing_key_bytes {
	    	Some(bytes) => Some(Signature::bytes_to_signingkey(bytes)?),
	    	None => None
	    };

		let mut encoding_thread_pool_manager = EncodingThreadPoolManager::new(
			obj_header.compression_header.clone(), obj_header.chunk_size as usize);

	    for h_type in hash_types {
			encoding_thread_pool_manager.add_hashing_thread(h_type.clone());
	    };

		let encoding_thread_pool_manager = Rc::new(RefCell::new(encoding_thread_pool_manager));

		let encryption_information = if let Some(encryption_key) = &encryption_key {
			obj_header.encryption_header.clone().map(|enc_header| EncryptionInformation::new(encryption_key.to_vec(), enc_header.algorithm.clone()))
		} else {
			None
		};

		let (filetype_encoding_information, file_header) = match logical_object_source.next() {
			Some((encoder, header)) => (encoder?, header),
			None => return Err(ZffError::new(
				ZffErrorKind::Missing,
				ERROR_NO_INPUT_FILE))
		};

		let current_file_number = file_header.file_number;


		let first_file_encoder = Some(FileEncoder::new(
			file_header,
			obj_header.clone(),
			filetype_encoding_information, 
			Rc::clone(&encoding_thread_pool_manager),
			signing_key.clone(),
			encryption_information, 
			current_chunk_number)?);
		
		let mut object_footer = ObjectFooterLogical::new_empty(obj_header.object_number);
		for filenumber in logical_object_source.root_dir_filenumbers() {
			object_footer.add_root_dir_filenumber(*filenumber)
		};

		Ok(Self {
			obj_header,
			logical_object_source,
			current_file_encoder: first_file_encoder,
			current_file_header_read: false,
			current_file_number,
			encoding_thread_pool_manager,
			encryption_key,
			signing_key,
			current_chunk_number,
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
	pub fn signing_key(&self) -> &Option<SigningKey> {
	    &self.signing_key
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

	/// Returns the next encoded data - an encoded [FileHeader], an encoded file chunk or an encoded [FileFooter](crate::footer::FileFooter).
	/// This method will increment the self.current_chunk_number automatically.
	pub(crate) fn get_next_data<D: Read + Seek>(
		&mut self, 
		current_offset: u64, 
		current_segment_no: u64,
		deduplication_metadata: Option<&mut DeduplicationMetadata<D>>) -> Result<EncodingState> {
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
					let prepared_data = PreparedData::PreparedFileHeader(file_encoder.get_encoded_header());
					return Ok(EncodingState::PreparedData(prepared_data));
				}
				
				// return next chunk
				if !self.empty_file_eof {
					match file_encoder.get_next_chunk(deduplication_metadata)? {
						EncodingState::PreparedChunk(data) => {
							self.current_chunk_number += 1;
							if data.chunk_header.flags.empty_file {
								self.empty_file_eof = true;
							}
							let prepared_data = PreparedData::PreparedChunk(data);
							return Ok(EncodingState::PreparedData(prepared_data));
						},
						EncodingState::PreparedData(_) => unreachable!(),
						EncodingState::ReadEOF => (),
					};
				} else {
					self.empty_file_eof = false;
				};
	

				//return file footer, set next file_encoder
				let prepared_file_footer = PreparedData::PreparedFileFooter(file_encoder.get_encoded_footer()?);

				self.object_footer.add_file_footer_segment_number(self.current_file_number, current_segment_no);
				self.object_footer.add_file_footer_offset(self.current_file_number, current_offset);

				let (filetype_encoding_information, current_file_header) = match self.logical_object_source.next() {
					Some((enc_info, header)) => (enc_info?, header),
					None => {
						// if no files left, the acquisition ends and the date will be written to the object footer.
						// The appropriate file footer will be returned.
						self.object_footer.set_acquisition_end(OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64);
						self.current_file_encoder = None;
						return Ok(EncodingState::PreparedData(prepared_file_footer));
					}
				};
				let encryption_information = if let Some(encryption_key) = &self.encryption_key {
					self.obj_header.encryption_header.as_ref().map(|enc_header| EncryptionInformation::new(
						encryption_key.to_vec(), enc_header.algorithm.clone()))
				} else {
					None
				};
				self.current_file_number = current_file_header.file_number;
       			
			    self.current_file_header_read = false;
				self.current_file_encoder = Some(FileEncoder::new(
					current_file_header, 
					self.obj_header.clone(),
					filetype_encoding_information, 
					Rc::clone(&self.encoding_thread_pool_manager),
					self.signing_key.clone(),
					encryption_information, 
					self.current_chunk_number)?);
				Ok(EncodingState::PreparedData(prepared_file_footer))
			},
			None => {
				self.object_footer.set_acquisition_end(OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64);
				Ok(EncodingState::ReadEOF)
			},
		}	
	}

	/// Returns the underlying encryption key (if available).
	pub fn encryption_key(&self) -> Option<Vec<u8>> {
		self.encryption_key.clone()
	}

}