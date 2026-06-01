// - Parent
use super::{*, footer::*};


/// The [PhysicalObjectEncoder] can be used to encode a physical object.
pub struct PhysicalObjectEncoder<R: Read> {
	/// The appropriate object header
	pub(crate) obj_header: ObjectHeader,
	pub(crate) underlying_data: R,
	pub(crate) read_bytes_underlying_data: u64,
	pub(crate) current_chunk_number: u64,
	pub(crate) initial_chunk_number: u64,
	pub(crate) encoding_thread_pool_manager: EncodingThreadPoolManager,
	pub(crate) signing_key: Option<SigningKey>,
	pub(crate) encryption_key: Option<Vec<u8>>,
	pub(crate) acquisition_start: u64,
	pub(crate) acquisition_end: u64,
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
	pub(crate) fn get_next_chunk<D: ReadAt>(
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