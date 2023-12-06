// - STD
use core::borrow::Borrow;
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
	encryption::EncryptionAlgorithm,
	DEFAULT_LENGTH_HEADER_IDENTIFIER,
	DEFAULT_LENGTH_VALUE_HEADER_LENGTH,
	HEADER_IDENTIFIER_FILE_HEADER,
	ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER,
	DEFAULT_HEADER_VERSION_FILE_HEADER,
};

use crate::header::EncryptionInformation;

// - external
#[cfg(feature = "serde")]
use serde::{
	Deserialize,
	Serialize,
};

/// Defines all file types, which are implemented for zff files.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq,Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum FileType {
	/// Represents a regular file (e.g. like "textfile.txt").
	File = 1,
	/// Represents a directory.
	Directory = 2,
	/// Represents a symbolic link.
	Symlink = 3,
	/// Represents a hard link (mostly used at unix like operating systems).
	Hardlink = 4,
	/// Represents a special file (like a FIFO, a char or block device).
	SpecialFile = 5,
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let msg = match self {
			FileType::File => "File",
			FileType::Directory => "Directory",
			FileType::Symlink => "Symlink",
			FileType::Hardlink => "Hardlink",
			FileType::SpecialFile => "SpecialFile",
		};
		write!(f, "{}", msg)
	}
}

/// Defines all unix special file types
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq,Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum SpecialFileType {
	/// Represents a Fifo.
	Fifo = 0,
	/// Represents a char device.
	Char = 1,
	/// Represents a block device.
	Block = 2,
}

impl TryFrom<u8> for SpecialFileType {
	type Error = ZffError;
	fn try_from(byte: u8) -> Result<Self> {
		match byte {
			0 => Ok(SpecialFileType::Fifo),
			1 => Ok(SpecialFileType::Char),
			2 => Ok(SpecialFileType::Block),
			_ => Err(ZffError::new(ZffErrorKind::UnknownFileType, byte.to_string())),
		}
	}
}

impl TryFrom<&u8> for SpecialFileType {
	type Error = ZffError;
	fn try_from(byte: &u8) -> Result<Self> {
		match byte {
			0 => Ok(SpecialFileType::Fifo),
			1 => Ok(SpecialFileType::Char),
			2 => Ok(SpecialFileType::Block),
			_ => Err(ZffError::new(ZffErrorKind::UnknownFileType, byte.to_string())),
		}
	}
}

impl fmt::Display for SpecialFileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let msg = match self {
			SpecialFileType::Fifo => "Fifo",
			SpecialFileType::Char => "Char",
			SpecialFileType::Block => "Block",
		};
		write!(f, "{}", msg)
	}
}

/// Each dumped file* contains a [FileHeader] containing several metadata.
/// The following metadata are included in a [FileHeader]:
/// - the internal file number of the appropriate file.
/// - the [FileType] of the appropriate file.
/// - the original filename of the appropriate file **without** the full path (just the filename, e.g. "my_texfile.txt" or "my_directory")
/// - the file number of the parent directory of this file (if the file lies into the root directory, this is 0 because the first valid file number in zff is 1).
/// - A HashMap to extend the metadata based on the operating system/filesystem. Some fields are predefined, see [the full list in the wiki](https://github.com/ph0llux/zff/wiki/zff-header-layout#file-metadata-extended-information)
#[derive(Debug,Clone,Eq,PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct FileHeader {
	/// The appropriate filenumber.
	pub file_number: u64,
	/// The appropriate filetype.
	pub file_type: FileType,
	/// The appropriate filename. 
	pub filename: String,
	/// The parent file number of this file. Will be 0, if the parent is the root directory.
	pub parent_file_number: u64,
	/// A [HashMap] of the metadata of this file.
	pub metadata_ext: HashMap<String, String>,
} 

impl FileHeader {
	/// creates a new [FileHeader] with the given values.
	pub fn new<F: Into<String>>(
		file_number: u64,
		file_type: FileType,
		filename: F,
		parent_file_number: u64,
		metadata_ext: HashMap<String, String>) -> FileHeader {
		Self {
			file_number,
			file_type,
			filename: filename.into(),
			parent_file_number,
			metadata_ext
		}
	}

	/// transforms the inner [FileType] to a [FileType::Hardlink]. This does not work with a [FileType::Symlink]!
	pub fn transform_to_hardlink(&mut self) {
		if self.file_type != FileType::Symlink {
			self.file_type = FileType::Hardlink
		}
	}

	/// encodes the file header to a ```Vec<u8>```. The encryption flag of the appropriate object header has to be set to 2.
	/// # Error
	/// The method returns an error, if the encryption fails.
	pub fn encode_encrypted_header_directly<E>(&self, encryption_information: E) -> Result<Vec<u8>>
	where
		E: Borrow<EncryptionInformation>
	{
		let mut vec = Vec::new();
		let encryption_information = encryption_information.borrow();
		let mut encoded_header = self.encode_encrypted_header(&encryption_information.encryption_key, &encryption_information.algorithm)?;
		let identifier = HEADER_IDENTIFIER_FILE_HEADER;
		let encoded_header_length = 4 + 8 + (encoded_header.len() as u64); //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.append(&mut encoded_header);

		Ok(vec)
	}

	fn encode_encrypted_header<K, A>(&self, key: K, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		let mut vec = Vec::new();
		vec.append(&mut self.version().encode_directly());
		vec.append(&mut self.file_number.encode_directly());

		let mut data_to_encrypt = Vec::new();
		data_to_encrypt.append(&mut self.encode_content());

		let encrypted_data = Encryption::encrypt_file_header(
			key, data_to_encrypt,
			self.file_number,
			algorithm
			)?;
		vec.append(&mut encrypted_data.encode_directly());
		Ok(vec)
	}

	fn encode_content(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut (self.file_type.clone() as u8).encode_directly());
		vec.append(&mut self.filename.encode_directly());
		vec.append(&mut self.parent_file_number.encode_directly());
		vec.append(&mut self.metadata_ext.encode_directly());
		vec
	}

	/// decodes the encrypted header with the given key and [crate::header::EncryptionHeader].
	/// The appropriate [crate::header::EncryptionHeader] has to be stored in the appropriate [crate::header::ObjectHeader].
	pub fn decode_encrypted_header_with_key<R, E>(data: &mut R, encryption_information: E) -> Result<FileHeader>
	where
		R: Read,
		E: Borrow<EncryptionInformation>
	{
		if !Self::check_identifier(data) {
			return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER));
		};
		let header_length = Self::decode_header_length(data)? as usize;
		let mut header_content = vec![0u8; header_length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
		data.read_exact(&mut header_content)?;
		let mut cursor = Cursor::new(header_content);
		let version = u8::decode_directly(&mut cursor)?;
		if version != DEFAULT_HEADER_VERSION_FILE_HEADER {
			return Err(ZffError::new(ZffErrorKind::UnsupportedVersion, version.to_string()))
		};
		let file_number = u64::decode_directly(&mut cursor)?;
		
		let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
		let algorithm = &encryption_information.borrow().algorithm;
		let decrypted_data = Encryption::decrypt_file_header(
			&encryption_information.borrow().encryption_key, 
			encrypted_data, 
			file_number, 
			algorithm)?;
		let mut cursor = Cursor::new(decrypted_data);
		let (file_type,
			filename,
			parent_file_number,
			metadata_ext) = Self::decode_inner_content(&mut cursor)?;
		let file_header = Self::new(
			file_number,
			file_type,
			filename,
			parent_file_number,
			metadata_ext);
		Ok(file_header)
	}

	#[allow(clippy::type_complexity)]
	fn decode_inner_content<R: Read>(inner_content: &mut R) -> Result<(
		FileType,
		String, //Filename
		u64, //parent_file_number
		HashMap<String, String>,
		)> {
		let file_type = match u8::decode_directly(inner_content)? {
			1 => FileType::File,
			2 => FileType::Directory,
			3 => FileType::Symlink,
			4 => FileType::Hardlink,
			val => return Err(ZffError::new(ZffErrorKind::UnknownFileType, val.to_string()))
		};
		let filename = String::decode_directly(inner_content)?;
		let parent_file_number = u64::decode_directly(inner_content)?;
		let metadata_ext = HashMap::<String, String>::decode_directly(inner_content)?;

		let inner_content = (
			file_type,
			filename,
			parent_file_number,
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
		DEFAULT_HEADER_VERSION_FILE_HEADER
	}
	
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.version().encode_directly());
		vec.append(&mut self.file_number.encode_directly());
		vec.append(&mut self.encode_content());
		vec
		
	}

	fn decode_content(data: Vec<u8>) -> Result<FileHeader> {
		let mut cursor = Cursor::new(data);
		let version = u8::decode_directly(&mut cursor)?;
		if version != DEFAULT_HEADER_VERSION_FILE_HEADER {
			return Err(ZffError::new(ZffErrorKind::UnsupportedVersion, version.to_string()))
		};
		let file_number = u64::decode_directly(&mut cursor)?;
		let (file_type, filename, parent_file_number, metadata_ext) = Self::decode_inner_content(&mut cursor)?;
		Ok(FileHeader::new(file_number, file_type, filename, parent_file_number, metadata_ext))
	}
}

// - implement fmt::Display
impl fmt::Display for FileHeader {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl FileHeader {
	fn struct_name(&self) -> &'static str {
		"FileHeader"
	}
}