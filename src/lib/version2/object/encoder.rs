// - STD
use std::os::unix::fs::MetadataExt;
use std::io::{Read, Cursor, Seek, SeekFrom};
use std::fs::{File};
use std::path::{PathBuf};
use std::collections::{HashMap};
use std::time::{SystemTime};

// - internal
use crate::{
	Result,
	buffer_chunk,
	calculate_crc32,
	compress_buffer,
	HeaderCoding,
	HashType,
	Hash,
	Signature,
	ZffError,
	ZffErrorKind,
	Encryption,
	DEFAULT_HEADER_VERSION_CHUNK_HEADER,
	DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_PHYSICAL,
	DEFAULT_HEADER_VERSION_HASH_VALUE_HEADER,
	DEFAULT_HEADER_VERSION_HASH_HEADER,
	DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_LOGICAL,
};

use crate::{
	header::{ObjectHeader, MainHeader, ChunkHeader, HashValue, HashHeader, FileHeader, CompressionHeader, EncryptionHeader},
	footer::{ObjectFooterPhysical, ObjectFooterLogical},
	FileEncoder, 
};

// - external
use digest::DynDigest;
use ed25519_dalek::{Keypair};
use time::{OffsetDateTime};

/// An encoder for each object. This is a wrapper Enum for [PhysicalObjectEncoder] and [LogicalObjectEncoder].
pub enum ObjectEncoder<R: Read> {
	/// Wrapper for [PhysicalObjectEncoder].
	Physical(PhysicalObjectEncoder<R>),
	/// Wrapper for [LogicalObjectEncoder].
	Logical(Box<LogicalObjectEncoder>),
}

impl<R: Read> ObjectEncoder<R> {
	/// returns the appropriate object number.
	pub fn obj_number(&self) -> u64 {
		match self {
			ObjectEncoder::Physical(obj) => obj.obj_number,
			ObjectEncoder::Logical(obj) => obj.obj_number,
		}
	}

	/// returns the current chunk number.
	pub fn current_chunk_number(&self) -> u64 {
		match self {
			ObjectEncoder::Physical(obj) => obj.current_chunk_number,
			ObjectEncoder::Logical(obj) => obj.current_chunk_number,
		}
	}

	/// returns the appropriate encoded [ObjectHeader].
	pub fn get_encoded_header(&mut self) -> Vec<u8> {
		match self {
			ObjectEncoder::Physical(obj) => obj.get_encoded_header(),
			ObjectEncoder::Logical(obj) => obj.get_encoded_header(),
		}
	}

	/// returns the underlying [MainHeader].
	pub fn main_header(&self) -> &MainHeader {
		match self {
			ObjectEncoder::Physical(obj) => obj.main_header(),
			ObjectEncoder::Logical(obj) => obj.main_header(),
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
	pub fn get_encoded_footer(&mut self) -> Vec<u8> {
		match self {
			ObjectEncoder::Physical(obj) => obj.get_encoded_footer(),
			ObjectEncoder::Logical(obj) => obj.get_encoded_footer(),
		}
	}

	/// returns the next data.
	pub fn get_next_data(&mut self, current_offset: u64, current_segment_no: u64) -> Result<Vec<u8>> {
		match self {
			ObjectEncoder::Physical(obj) => obj.get_next_chunk(),
			ObjectEncoder::Logical(obj) => obj.get_next_data(current_offset, current_segment_no),
		}
	}

}

/// The [PhysicalObjectEncoder] can be used to encode a physical object.
pub struct PhysicalObjectEncoder<R: Read> {
	/// The number of this object
	obj_number: u64,
	///An encoded [ObjectHeader].
	encoded_header: Vec<u8>,
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
	encryption_key: Option<Vec<u8>>,
	signature_key: Option<Keypair>,
	main_header: MainHeader,
	compression_header: CompressionHeader,
	encryption_header: Option<EncryptionHeader>,
	has_hash_signatures: bool,
	acquisition_start: u64,
	acquisition_end: u64,
}

impl<R: Read> PhysicalObjectEncoder<R> {
	/// Returns a new [PhysicalObjectEncoder] by the given values.
	pub fn new(
		obj_header: ObjectHeader,
		reader: R,
		hash_types: Vec<HashType>,
		encryption_key: Option<Vec<u8>>,
		signature_key_bytes: Option<Vec<u8>>,
		main_header: MainHeader,
		current_chunk_number: u64,
		header_encryption: bool) -> Result<PhysicalObjectEncoder<R>> {
		
		let signature_key = match &signature_key_bytes {
	    	Some(bytes) => Some(Keypair::from_bytes(bytes)?),
	    	None => None
	    };

		let encoded_header = if header_encryption {
			if let Some(ref encryption_key) = encryption_key {
				obj_header.encode_encrypted_header_directly(encryption_key)?
			} else {
				return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, ""));
			}
		} else {
			obj_header.encode_directly()
		};
		let mut hasher_map = HashMap::new();
	    for h_type in hash_types {
	        let hasher = Hash::new_hasher(&h_type);
	        hasher_map.insert(h_type.clone(), hasher);
	    };
		Ok(Self {
			obj_number: obj_header.object_number(),
			encoded_header_remaining_bytes: encoded_header.len(),
			encoded_header,
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
			main_header,
			compression_header: obj_header.compression_header(),
			encryption_header: obj_header.encryption_header().map(ToOwned::to_owned),
			has_hash_signatures: obj_header.has_hash_signatures(),
			acquisition_start: 0,
			acquisition_end: 0,
		})
	}

	fn update_hasher(&mut self, buffer: &[u8]) {
		for hasher in self.hasher_map.values_mut() {
			hasher.update(buffer);
		}
	}

	/// Returns the appropriate object number.
	pub fn obj_number(&self) -> u64 {
		self.obj_number
	}

	/// Returns the current chunk number.
	pub fn current_chunk_number(&self) -> u64 {
		self.current_chunk_number
	}

	/// Returns the encoded header. A call of this method sets the acquisition start time to the current time.
	pub fn get_encoded_header(&mut self) -> Vec<u8> {
		self.acquisition_start = OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64;
		self.encoded_header.clone()
	}


	/// Returns the encoded Chunk - this method will increment the self.current_chunk_number automatically.
	pub fn get_next_chunk(&mut self) -> Result<Vec<u8>> {
		let mut chunk = Vec::new();

		// prepare chunked data:
	    let chunk_size = self.main_header.chunk_size();
	    let (buf, read_bytes) = buffer_chunk(&mut self.underlying_data, chunk_size as usize)?;
	    self.read_bytes_underlying_data += read_bytes;
	    if buf.is_empty() {
	    	return Err(ZffError::new(ZffErrorKind::ReadEOF, ""));
	    };
	    self.update_hasher(&buf);
	    let crc32 = calculate_crc32(&buf);
	    let signature = Signature::calculate_signature(self.signature_key.as_ref(), &buf);

	    let (chunked_data, compression_flag) = compress_buffer(buf, self.main_header.chunk_size(), &self.compression_header)?;

	    // prepare chunk header:
	    let mut chunk_header = ChunkHeader::new_empty(DEFAULT_HEADER_VERSION_CHUNK_HEADER, self.current_chunk_number);  
	    chunk_header.set_crc32(crc32);
	    chunk_header.set_signature(signature);
	    if compression_flag {
			chunk_header.set_compression_flag()
		}
		let mut chunked_data = match &self.encryption_key {
			Some(encryption_key) => {
				let encryption_algorithm = match &self.encryption_header {
					Some(header) => header.algorithm(),
					None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionHeader, "")),
				};
				
				Encryption::encrypt_message(
					encryption_key,
					&chunked_data,
					chunk_header.chunk_number(),
					encryption_algorithm)?
			},
			None => chunked_data,
		};
		
		chunk_header.set_chunk_size(chunked_data.len() as u64);
		chunk.append(&mut chunk_header.encode_directly());
		chunk.append(&mut chunked_data);
		self.current_chunk_number += 1;
	    Ok(chunk)
	}

	/// Generates a appropriate footer. Attention: A call of this method ...
	/// - sets the acquisition end time to the current time
	/// - finalizes the underlying hashers
	pub fn get_encoded_footer(&mut self) -> Vec<u8> {
		self.acquisition_end = OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64;
		let mut hash_values = Vec::new();
	    for (hash_type, hasher) in self.hasher_map.clone() {
	        let hash = hasher.finalize();
	        let mut hash_value = HashValue::new_empty(DEFAULT_HEADER_VERSION_HASH_VALUE_HEADER, hash_type);
	        hash_value.set_hash(hash.to_vec());
	        if self.has_hash_signatures {
	        	let signature = Signature::calculate_signature(self.signature_key.as_ref(), &hash.to_vec());
	        	if let Some(sig) = signature { hash_value.set_ed25519_signature(sig) };
	        };
	        hash_values.push(hash_value);
	    }
	    let hash_header = HashHeader::new(DEFAULT_HEADER_VERSION_HASH_HEADER, hash_values);
		let footer = ObjectFooterPhysical::new(
			DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_PHYSICAL,
			self.acquisition_start,
			self.acquisition_end,
			self.read_bytes_underlying_data as u64,
			self.initial_chunk_number,
			self.current_chunk_number - self.initial_chunk_number,
			hash_header);
		footer.encode_directly()
	}

	/// Returns the underlying [MainHeader].
	pub fn main_header(&self) -> &MainHeader {
		&self.main_header
	}

	/// Returns the underlying encryption key (if available).
	pub fn encryption_key(&self) -> Option<Vec<u8>> {
		self.encryption_key.clone()
	}
}

/// This implement Read for [PhysicalObjectEncoder]. This implementation should only used for a single zff segment file (e.g. in http streams).
impl<D: Read> Read for PhysicalObjectEncoder<D> {
	fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
		let mut read_bytes = 0;
		//read encoded header, if there are remaining bytes to read.
        if let remaining_bytes @ 1.. = self.encoded_header_remaining_bytes {
            let mut inner_read_bytes = 0;
            let mut inner_cursor = Cursor::new(&self.encoded_header);
            inner_cursor.seek(SeekFrom::End(-(remaining_bytes as i64)))?;
            inner_read_bytes += inner_cursor.read(&mut buf[read_bytes..])?;
            self.encoded_header_remaining_bytes -= inner_read_bytes;
            read_bytes += inner_read_bytes;
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
}

/// The [LogicalObjectEncoder] can be used to encode a logical object.
pub struct LogicalObjectEncoder {
	/// The number of this object
	obj_number: u64,
	encoded_header: Vec<u8>,
	//encoded_header_remaining_bytes: usize,
	files: Vec<(PathBuf, FileHeader)>,
	current_file_encoder: Option<FileEncoder>,
	current_file_header_read: bool,
	current_file_number: u64,
	hash_types: Vec<HashType>,
	encryption_key: Option<Vec<u8>>,
	signature_key_bytes: Option<Vec<u8>>,
	main_header: MainHeader,
	compression_header: CompressionHeader,
	encryption_header: Option<EncryptionHeader>,
	current_chunk_number: u64,
	symlink_real_paths: HashMap<u64, PathBuf>,
	hardlink_map: HashMap<u64, HashMap<u64, u64>>, // <dev_id, <inode, file number>>
	directory_children: HashMap<u64, Vec<u64>>, //<directory file number, Vec<child filenumber>>
	object_footer: ObjectFooterLogical,
	header_encryption: bool,
}

impl LogicalObjectEncoder {
	/// Returns the encoded footer for this object.
	pub fn get_encoded_footer(&self) -> Vec<u8> {
		self.object_footer.encode_directly()
	}

	/// Returns a new [LogicalObjectEncoder] by the given values.
	pub fn new(
		obj_header: ObjectHeader,
		files: Vec<(PathBuf, FileHeader)>,
		root_dir_filenumbers: Vec<u64>,
		hash_types: Vec<HashType>,
		encryption_key: Option<Vec<u8>>,
		signature_key_bytes: Option<Vec<u8>>,
		main_header: MainHeader,
		symlink_real_paths: HashMap<u64, PathBuf>, //File number <-> Symlink real path
		hardlink_map: HashMap<u64, HashMap<u64, u64>>, // <dev_id, <inode, file number>>
		directory_children: HashMap<u64, Vec<u64>>,
		current_chunk_number: u64,
		header_encryption: bool) -> Result<LogicalObjectEncoder> {		

		let encoded_header = if header_encryption {
			if let Some(ref encryption_key) = encryption_key {
				obj_header.encode_encrypted_header_directly(encryption_key)?
			} else {
				return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, ""));
			}
		} else {
			obj_header.encode_directly()
		};

		let mut files = files;
		let (current_path, mut current_file_header) = match files.pop() {
			Some((file, header)) => (file, header),
			None => return Err(ZffError::new(ZffErrorKind::NoFilesLeft, "There is no input file"))
		};
		let current_file = File::open(&current_path)?;
		let current_file_number = current_file_header.file_number();
		let symlink_real_path = symlink_real_paths.get(&current_file_number).cloned();
		let current_directory_children = match directory_children.get(&current_file_number) {
			Some(children) => children.to_owned(),
			None => Vec::new()
		};
		let signature_key = match &signature_key_bytes {
	    	Some(bytes) => Some(Keypair::from_bytes(bytes)?),
	    	None => None
	    };
	    let metadata = current_file.metadata()?;
	    let encryption_header = obj_header.encryption_header().map(ToOwned::to_owned);

	    let mut hardlink_filenumber = None;
	    if let Some(inner_map) = hardlink_map.get(&metadata.dev()) {
    		if let Some(fno) = inner_map.get(&metadata.ino()) {
				if *fno != current_file_header.file_number() {
					current_file_header.transform_to_hardlink();
					hardlink_filenumber = Some(*fno);
				};
	    	}
     	}
		let first_file_encoder = Some(FileEncoder::new(current_file_header, current_file, hash_types.clone(), encryption_key.clone(), signature_key, main_header.clone(), obj_header.compression_header(), encryption_header.clone(), current_chunk_number, symlink_real_path, header_encryption, hardlink_filenumber, current_directory_children)?);
		
		let mut object_footer = ObjectFooterLogical::new_empty(DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_LOGICAL);
		for filenumber in root_dir_filenumbers {
			object_footer.add_root_dir_filenumber(filenumber)
		};

		Ok(Self {
			obj_number: obj_header.object_number(),
			//encoded_header_remaining_bytes: encoded_header.len(),
			encoded_header,
			files,
			current_file_encoder: first_file_encoder,
			current_file_header_read: false,
			current_file_number,
			hash_types,
			encryption_key,
			signature_key_bytes,
			main_header,
			compression_header: obj_header.compression_header(),
			encryption_header,
			current_chunk_number,
			symlink_real_paths,
			hardlink_map,
			directory_children,
			object_footer,
			header_encryption,
		})
	}

	/// Returns the appropriate object number.
	pub fn obj_number(&self) -> u64 {
		self.obj_number
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
		self.encoded_header.clone()
	}

	/// Returns the next encoded data - an encoded [FileHeader], an encoded file chunk or an encoded [FileFooter].
	/// This method will increment the self.current_chunk_number automatically.
	pub fn get_next_data(&mut self, current_offset: u64, current_segment_no: u64) -> Result<Vec<u8>> {
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
				match file_encoder.get_next_chunk() {
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
				let file_footer = file_encoder.get_encoded_footer();
				self.object_footer.add_file_footer_segment_number(self.current_file_number, current_segment_no);
				self.object_footer.add_file_footer_offset(self.current_file_number, current_offset);
				let (current_path, mut current_file_header) = match self.files.pop() {
					Some((file, header)) => (file, header),
					None => {
						self.current_file_encoder = None;
						return Ok(file_footer)
					},
				};
				let current_file = File::open(&current_path)?;
				self.current_file_number = current_file_header.file_number();
				let symlink_real_path = self.symlink_real_paths.get(&self.current_file_number).cloned();
				let current_directory_children = match self.directory_children.get(&self.current_file_number) {
					Some(children) => children.to_owned(),
					None => Vec::new(),
				};
				let signature_key = match &self.signature_key_bytes {
			    	Some(bytes) => Some(Keypair::from_bytes(bytes)?),
			    	None => None
			    };

			    let metadata = current_file.metadata()?;

			    // transform the next header to hardlink, if the file is one.
			    let mut hardlink_filenumber = None;
			    if let Some(inner_map) = self.hardlink_map.get(&metadata.dev()) {
		    		if let Some(fno) = inner_map.get(&metadata.ino()) {
	    				if *fno != current_file_header.file_number() {
	    					current_file_header.transform_to_hardlink();
	    					hardlink_filenumber = Some(*fno);
	    				};
    			    }
       			}
			    self.current_file_header_read = false;
				self.current_file_encoder = Some(FileEncoder::new(current_file_header, current_file, self.hash_types.clone(), self.encryption_key.clone(), signature_key, self.main_header.clone(), self.compression_header.clone(), self.encryption_header.clone(), self.current_chunk_number, symlink_real_path, self.header_encryption, hardlink_filenumber, current_directory_children)?);
				Ok(file_footer)
			},
			None => {
				self.object_footer.set_acquisition_end(OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64);
				Err(ZffError::new(ZffErrorKind::ReadEOF, ""))
			},
		}	
	}

	/// Returns a reference to the underlying [MainHeader].
	pub fn main_header(&self) -> &MainHeader {
		&self.main_header
	}

	/// Returns the underlying encryption key (if available).
	pub fn encryption_key(&self) -> Option<Vec<u8>> {
		self.encryption_key.clone()
	}

}