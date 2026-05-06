// - Parent
use super::{*, footer::*};


/// The [LogicalObjectEncoder] can be used to encode a logical object.
pub struct LogicalObjectEncoder {
	/// The appropriate original object header
	pub(crate) obj_header: ObjectHeader,
	//encoded_header_remaining_bytes: usize,
	pub(crate) logical_object_source: Box<dyn LogicalObjectSource>,
	pub(crate) current_file_encoder: Option<FileEncoder>,
	pub(crate) current_file_header_read: bool,
	pub(crate) current_file_number: u64,
	pub(crate) encoding_thread_pool_manager: Rc<RefCell<EncodingThreadPoolManager>>,
	pub(crate) encryption_key: Option<Vec<u8>>,
	pub(crate) signing_key: Option<SigningKey>,
	pub(crate) current_chunk_number: u64,
	pub(crate) object_footer: ObjectFooterLogical,
	pub(crate) empty_file_eof: bool,
}

impl LogicalObjectEncoder {
	/// Returns the encoded footer for this object.
	/// Sets the acquisition end timestamp of the object footer to current system time.
	pub fn get_encoded_footer(&mut self) -> Result<Vec<u8>> {
		self.object_footer.replace_root_dir_filenumbers(self.logical_object_source.root_dir_filenumbers());
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
			Some(res) => res?,
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
		
		let object_footer = ObjectFooterLogical::new_empty(obj_header.object_number);

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
					Some(res) => res?,
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