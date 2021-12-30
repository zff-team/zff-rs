// - STD
use std::io::Cursor;
use std::fmt;

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueDecoder,
	ValueEncoder,
	ZffError,
	ZffErrorKind,
	HEADER_IDENTIFIER_FILE_HEADER,
};

// - external
use serde::{Serialize};

/// Defines all hashing algorithms, which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq,Hash,Serialize)]
pub enum FileType {
	File = 1,
	Directory = 2,
	Symlink = 3,
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let msg = match self {
			FileType::File => "File",
			FileType::Directory => "Directory",
			FileType::Symlink => "Symlink",
		};
		write!(f, "{}", msg)
	}
}

#[derive(Debug,Clone)]
pub struct FileHeader {
	version: u8,
	file_number: u64,
	file_type: FileType,
	filename: String,
	parent_file_number: u64,
}

impl FileHeader {
	pub fn new<F: Into<String>>(version: u8, file_number: u64, file_type: FileType, filename: F, parent_file_number: u64) -> FileHeader {
		Self {
			version: version,
			file_number: file_number,
			file_type: file_type,
			filename: filename.into(),
			parent_file_number: parent_file_number,
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
		vec.push(self.file_type.clone() as u8);
		vec.append(&mut self.filename().encode_directly());
		vec.append(&mut self.parent_file_number.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<FileHeader> {
		let mut cursor = Cursor::new(data);
		let header_version = u8::decode_directly(&mut cursor)?;
		let file_number = u64::decode_directly(&mut cursor)?;
		let file_type = match u8::decode_directly(&mut cursor)? {
			1 => FileType::File,
			2 => FileType::Directory,
			3 => FileType::Symlink,
			val @ _ => return Err(ZffError::new(ZffErrorKind::UnknownObjectTypeValue, val.to_string()))
		};
		let filename = String::decode_directly(&mut cursor)?;
		let parent_file_number = u64::decode_directly(&mut cursor)?;
		
		Ok(FileHeader::new(header_version, file_number, file_type, filename, parent_file_number))
	}
}