// - STD
use std::path::Path;
use std::io::{Read};
use std::path::{PathBuf};
use std::collections::{HashMap};
use std::time::{SystemTime};

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
	DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_PHYSICAL,
	DEFAULT_HEADER_VERSION_HASH_VALUE_HEADER,
	DEFAULT_HEADER_VERSION_HASH_HEADER,
	DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_LOGICAL,
};

use crate::{
	header::{
		ObjectHeader, 
		HashHeader, 
		ChunkHeader, 
		HashValue, 
		FileHeader, 
		EncryptionInformation,
		DeduplicationChunkMap,
	},
	footer::{ObjectFooterPhysical, ObjectFooterLogical},
	FileEncoder,
	io::check_same_byte,
};

// - external
use digest::DynDigest;
use ed25519_dalek::{Keypair};
use time::{OffsetDateTime};

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
	/// remaining bytes of the encoded header to read. This is only (internally) used, if you will use the [Read] implementation of [PhysicalObjectEncoder].
	encoded_header_remaining_bytes: usize,
	underlying_data: R,
	read_bytes_underlying_data: u64,
	/// data of current chunk (only used in Read implementation)
	current_chunked_data: Option<Vec<u8>>,
	current_chunked_data_remaining_bytes: usize,
	current_chunk_number: u64,
	initial_chunk_number: u64,
	encoded_footer: Vec<u8>,
	encoded_footer_remaining_bytes: usize,
	hasher_map: HashMap<HashType, Box<dyn DynDigest>>,
	signature_key: Option<Keypair>,
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
		signature_key_bytes: Option<Vec<u8>>,
		current_chunk_number: u64) -> Result<PhysicalObjectEncoder<R>> {
		
		let signature_key = match &signature_key_bytes {
	    	Some(bytes) => Some(Keypair::from_bytes(bytes)?),
	    	None => None
	    };

		let (encoded_header, encryption_key) = if let Some(encryption_header) = &obj_header.encryption_header {
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
			encoded_header_remaining_bytes: encoded_header.len(),
			underlying_data: reader,
			read_bytes_underlying_data: 0,
			current_chunked_data: None,
			current_chunked_data_remaining_bytes: 0,
			current_chunk_number,
			initial_chunk_number: current_chunk_number,
			encoded_footer: Vec::new(),
			encoded_footer_remaining_bytes: 0,
			hasher_map,
			encryption_key,
			signature_key,
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

	/// Returns the encoded object header. A call of this method sets the acquisition start time to the current time.
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
	    	} else {
	    		deduplication_map.append_entry(self.current_chunk_number, b3h)?;
	    	}
	    	chunk_header.flags.duplicate = true;
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
	        	let signature = Signature::calculate_signature(self.signature_key.as_ref(), &hash);
	        	if let Some(sig) = signature { hash_value.set_ed25519_signature(sig) };
	        };
	        hash_values.push(hash_value);
	    }
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

/*/// This implement Read for [PhysicalObjectEncoder]. This implementation should only used for a single zff segment file (e.g. in http streams).
impl<D: Read> Read for PhysicalObjectEncoder<D> {
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
        			Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
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

pub enum FileRessource {
	ByPath(PathBuf),
	ByReader(Box<dyn Read>)
}

impl From<PathBuf> for FileRessource {
	fn from(path: PathBuf) -> Self {
		FileRessource::ByPath(path)
	}
}

/// The [LogicalObjectEncoder] can be used to encode a logical object.
pub struct LogicalObjectEncoder {
	/// The appropriate original object header
	obj_header: ObjectHeader,
	//encoded_header_remaining_bytes: usize,
	files: Vec<(Box<dyn Read>, FileHeader)>,
	current_file_encoder: Option<FileEncoder>,
	current_file_header_read: bool,
	current_file_number: u64,
	hash_types: Vec<HashType>,
	encryption_key: Option<Vec<u8>>,
	signature_key_bytes: Option<Vec<u8>>,
	current_chunk_number: u64,
	symlink_real_paths: HashMap<u64, PathBuf>,
	hardlink_map: HashMap<u64, u64>, //<filenumber, filenumber of hardlink>
	directory_children: HashMap<u64, Vec<u64>>, //<directory file number, Vec<child filenumber>>
	object_footer: ObjectFooterLogical,
	unaccessable_files: Vec<PathBuf>
}

impl LogicalObjectEncoder {
	/// Returns the encoded footer for this object.
	pub fn get_encoded_footer(&self) -> Result<Vec<u8>> {
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


	pub fn add_unaccessable_file<F>(&mut self, file_path: F)
	where
		F: AsRef<Path>
	{
		self.unaccessable_files.push(file_path.as_ref().to_path_buf())
	}

	/// Returns a new [LogicalObjectEncoder] by the given values.
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		obj_header: ObjectHeader,
		files: Vec<(Box<dyn Read>, FileHeader)>,
		root_dir_filenumbers: Vec<u64>,
		hash_types: Vec<HashType>,
		signature_key_bytes: Option<Vec<u8>>,
		symlink_real_paths: HashMap<u64, PathBuf>, //File number <-> Symlink real path
		hardlink_map: HashMap<u64, u64>, // <filenumber, filenumber of hardlink>
		directory_children: HashMap<u64, Vec<u64>>,
		current_chunk_number: u64) -> Result<LogicalObjectEncoder> {		

		//test if the encryption is successful.
		let (_encoded_header, encryption_key) = if let Some(encryption_header) = &obj_header.encryption_header {
			match encryption_header.get_encryption_key() {
				Some(key) => (obj_header.encode_encrypted_header_directly(&key)?, Some(key)),
				None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, obj_header.object_number.to_string()))
			}
	    } else {
	    	(obj_header.encode_directly(), None)
	    };

		let mut files = files; //TODO: ????
		let (reader, current_file_header) = match files.pop() {
			Some((file, header)) => (file, header),
			None => return Err(ZffError::new(ZffErrorKind::NoFilesLeft, "There is no input file"))
		};

		let current_file_number = current_file_header.file_number;
		let symlink_real_path = symlink_real_paths.get(&current_file_number).cloned();
		let current_directory_children = match directory_children.get(&current_file_number) {
			Some(children) => children.to_owned(),
			None => Vec::new()
		};
		let signature_key = match &signature_key_bytes {
	    	Some(bytes) => Some(Keypair::from_bytes(bytes)?),
	    	None => None
	    };
			    

     	let encryption_information = if let Some(encryption_key) = &encryption_key {
     		obj_header.encryption_header.clone().map(|enc_header| EncryptionInformation::new(encryption_key.to_vec(), enc_header.algorithm().clone()))
     	} else {
     		None
     	};

     	let hardlink_filenumber = hardlink_map.get(&current_file_number).copied();

		let first_file_encoder = Some(FileEncoder::new(
			current_file_header,
			obj_header.clone(),
			reader, 
			hash_types.clone(), 
			encryption_information, 
			signature_key, 
			current_chunk_number, 
			symlink_real_path, 
			hardlink_filenumber, 
			current_directory_children)?);
		
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
			signature_key_bytes,
			current_chunk_number,
			symlink_real_paths,
			hardlink_map,
			directory_children,
			object_footer,
			unaccessable_files: Vec::new(),
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
	pub fn signature_key(&self) -> Option<Keypair> {
	    match &self.signature_key_bytes {
	    	Some(bytes) => Keypair::from_bytes(bytes).ok(),
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
					self.object_footer.set_acquisition_start(OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64);
					self.object_footer.add_file_header_segment_number(self.current_file_number, current_segment_no);
					self.object_footer.add_file_header_offset(self.current_file_number, current_offset);
					return Ok(file_encoder.get_encoded_header());
				}

				// return next chunk
				match file_encoder.get_next_chunk(deduplication_map) {
					Ok(data) => {
						self.current_chunk_number += 1;
						return Ok(data);
					},
					Err(e) => match e.get_kind() {
						ZffErrorKind::ReadEOF => (),
						ZffErrorKind::NotAvailableForFileType => (),
						_ => return Err(e)
					}
				};

				//return file footer, set next file_encoder
				let file_footer = file_encoder.get_encoded_footer()?;
				self.object_footer.add_file_footer_segment_number(self.current_file_number, current_segment_no);
				self.object_footer.add_file_footer_offset(self.current_file_number, current_offset);
				
				let (reader, current_file_header) = match self.files.pop() {
					Some((file, header)) => (file, header),
					None => return Err(ZffError::new(ZffErrorKind::NoFilesLeft, "There is no input file"))
				};	    
		     	let hardlink_filenumber = self.hardlink_map.get(&self.current_file_number).copied();

				self.current_file_number = current_file_header.file_number;
				let symlink_real_path = self.symlink_real_paths.get(&self.current_file_number).cloned();
				let current_directory_children = match self.directory_children.get(&self.current_file_number) {
					Some(children) => children.to_owned(),
					None => Vec::new(),
				};
				let signature_key = match &self.signature_key_bytes {
			    	Some(bytes) => Some(Keypair::from_bytes(bytes)?),
			    	None => None
			    };

       			let encryption_information = if let Some(encryption_key) = &self.encryption_key {
		     		self.obj_header.encryption_header.as_ref().map(|enc_header| EncryptionInformation::new(encryption_key.to_vec(), enc_header.algorithm().clone()))
		     	} else {
		     		None
		     	};
       			
			    self.current_file_header_read = false;
				self.current_file_encoder = Some(FileEncoder::new(
					current_file_header, 
					self.obj_header.clone(),
					reader, 
					self.hash_types.clone(), 
					encryption_information, 
					signature_key, 
					self.current_chunk_number, 
					symlink_real_path, 
					hardlink_filenumber, 
					current_directory_children)?);
				Ok(file_footer)
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