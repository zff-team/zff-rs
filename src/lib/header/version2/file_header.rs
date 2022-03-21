// - STD
use std::io::{Cursor, Read};
use std::collections::HashMap;
use std::fmt;

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueDecoder,
	ValueEncoder,
	Encryption,
	ZffError,
	ZffErrorKind,
};

use crate::{
	DEFAULT_LENGTH_HEADER_IDENTIFIER,
	DEFAULT_LENGTH_VALUE_HEADER_LENGTH,
	HEADER_IDENTIFIER_FILE_HEADER,
	ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER
};

use crate::header::{
	EncryptionHeader,
};

/// Defines all hashing algorithms, which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq,Hash)]
pub enum FileType {
	File = 1,
	Directory = 2,
	Symlink = 3,
	Hardlink = 4,
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let msg = match self {
			FileType::File => "File",
			FileType::Directory => "Directory",
			FileType::Symlink => "Symlink",
			FileType::Hardlink => "Hardlink",
		};
		write!(f, "{}", msg)
	}
}

#[derive(Debug,Clone,Eq,PartialEq)]
pub struct FileHeader {
	version: u8,
	file_number: u64,
	file_type: FileType,
	filename: String,
	parent_file_number: u64,
	atime: u64,
	mtime: u64,
	ctime: u64,
	btime: u64,
	metadata_ext: HashMap<String, String>,
}

impl FileHeader {
	pub fn new<F: Into<String>>(
		version: u8,
		file_number: u64,
		file_type: FileType,
		filename: F,
		parent_file_number: u64,
		atime: u64,
		mtime: u64,
		ctime: u64,
		btime: u64,
		metadata_ext: HashMap<String, String>) -> FileHeader {
		Self {
			version: version,
			file_number: file_number,
			file_type: file_type,
			filename: filename.into(),
			parent_file_number: parent_file_number,
			atime: atime,
			mtime: mtime,
			ctime: ctime,
			btime: btime,
			metadata_ext: metadata_ext
		}
	}
	pub fn file_number(&self) -> u64 {
		self.file_number
	}
	pub fn file_type(&self) -> FileType {
		self.file_type.clone()
	}
	pub fn filename(&self) -> &str {
		&self.filename
	}
	pub fn parent_file_number(&self) -> u64 {
		self.parent_file_number
	}
	pub fn atime(&self) -> u64 {
		self.atime
	}
	pub fn mtime(&self) -> u64 {
		self.mtime
	}
	pub fn ctime(&self) -> u64 {
		self.ctime
	}
	pub fn btime(&self) -> u64 {
		self.btime
	}
	pub fn metadata_ext(&self) -> &HashMap<String, String> {
		&self.metadata_ext
	}
	pub fn transform_to_hardlink(&mut self) {
		self.file_type = FileType::Hardlink
	}

	/// encodes the file header to a ```Vec<u8>```. The encryption flag will be set to 2.
	/// # Error
	/// The method returns an error, if the encryption header is missing (=None).
	/// The method returns an error, if the encryption fails.
	pub fn encode_encrypted_header_directly<K>(&self, key: K, encryption_header: EncryptionHeader) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
	{
		let mut vec = Vec::new();
		let mut encoded_header = self.encode_encrypted_header(key, encryption_header)?;
		let identifier = HEADER_IDENTIFIER_FILE_HEADER;
		let encoded_header_length = 4 + 8 + (encoded_header.len() as u64); //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.append(&mut encoded_header);

		Ok(vec)
	}

	fn encode_encrypted_header<K>(&self, key: K, encryption_header: EncryptionHeader) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>
	{
		let mut vec = Vec::new();
		vec.push(self.version);
		vec.append(&mut self.file_number.encode_directly());

		let mut data_to_encrypt = Vec::new();
		data_to_encrypt.append(&mut self.encode_content());

		let encrypted_data = Encryption::encrypt_header(
			key, data_to_encrypt,
			encryption_header.nonce(),
			encryption_header.algorithm()
			)?;
		vec.append(&mut encrypted_data.encode_directly());
		return Ok(vec);
	}

	fn encode_content(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		
		vec.push(self.file_type.clone() as u8);
		vec.append(&mut self.filename().encode_directly());
		vec.append(&mut self.parent_file_number.encode_directly());
		vec.append(&mut self.atime.encode_directly());
		vec.append(&mut self.mtime.encode_directly());
		vec.append(&mut self.ctime.encode_directly());
		vec.append(&mut self.btime.encode_directly());
		vec.append(&mut self.metadata_ext.encode_directly());
		vec
	}

	/// decodes the encrypted header with the given key.
	pub fn decode_encrypted_header_with_key<R, K>(data: &mut R, key: K, encryption_header: EncryptionHeader) -> Result<FileHeader>
	where
		R: Read,
		K: AsRef<[u8]>,
	{
		if !Self::check_identifier(data) {
			return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER));
		};
		let header_length = Self::decode_header_length(data)? as usize;
		let mut header_content = vec![0u8; header_length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
		data.read_exact(&mut header_content)?;
		let mut cursor = Cursor::new(header_content);
		let header_version = u8::decode_directly(&mut cursor)?;
		let file_number = u64::decode_directly(&mut cursor)?;
		
		let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
		let nonce = encryption_header.nonce();
		let algorithm = encryption_header.algorithm();
		let decrypted_data = Encryption::decrypt_header(key, encrypted_data, nonce, algorithm)?;
		let mut cursor = Cursor::new(decrypted_data);
		let (file_type,
			filename,
			parent_file_number,
			atime,
			mtime,
			ctime,
			btime,
			metadata_ext) = Self::decode_inner_content(&mut cursor)?;
		let file_header = Self::new(
			header_version,
			file_number,
			file_type,
			filename,
			parent_file_number,
			atime,
			mtime,
			ctime,
			btime,
			metadata_ext);
		Ok(file_header)
	}

	fn decode_inner_content<R: Read>(inner_content: &mut R) -> Result<(
		FileType,
		String, //Filename
		u64, //parent_file_number
		u64, //atime,
		u64, //mtime
		u64, //ctime,
		u64, //btime,
		HashMap<String, String>,
		)> {
		let file_type = match u8::decode_directly(inner_content)? {
			1 => FileType::File,
			2 => FileType::Directory,
			3 => FileType::Symlink,
			val @ _ => return Err(ZffError::new(ZffErrorKind::UnknownObjectTypeValue, val.to_string()))
		};
		let filename = String::decode_directly(inner_content)?;
		let parent_file_number = u64::decode_directly(inner_content)?;
		let atime = u64::decode_directly(inner_content)?;
		let mtime = u64::decode_directly(inner_content)?;
		let ctime = u64::decode_directly(inner_content)?;
		let btime = u64::decode_directly(inner_content)?;
		let metadata_ext = HashMap::<String, String>::decode_directly(inner_content)?;

		let inner_content = (
			file_type,
			filename,
			parent_file_number,
			atime,
			mtime,
			ctime,
			btime,
			metadata_ext);
		Ok(inner_content)
	}
}

impl HeaderCoding for FileHeader {
	type Item = FileHeader;
	
	fn identifier() -> u32 {
		HEADER_IDENTIFIER_FILE_HEADER
	}

	fn version(&self) -> u8 {
		self.version
	}
	
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(self.version);
		vec.append(&mut self.file_number.encode_directly());
		vec.append(&mut self.encode_content());
		vec
		
	}

	fn decode_content(data: Vec<u8>) -> Result<FileHeader> {
		let mut cursor = Cursor::new(data);
		let header_version = u8::decode_directly(&mut cursor)?;
		let file_number = u64::decode_directly(&mut cursor)?;
		let (file_type, filename, parent_file_number, atime, mtime, ctime, btime, metadata_ext) = Self::decode_inner_content(&mut cursor)?;
		Ok(FileHeader::new(header_version, file_number, file_type, filename, parent_file_number, atime, mtime, ctime, btime, metadata_ext))
	}
}