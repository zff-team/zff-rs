// - STD
use std::io::Cursor;

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueDecoder,
	ValueEncoder,
	FOOTER_IDENTIFIER_FILE_FOOTER,
};
use crate::version2::header::{
	HashHeader,
};

#[derive(Debug,Clone)]
pub struct FileFooter {
	version: u8,
	hash_header: HashHeader,
	number_of_chunks: u64
}

impl FileFooter {
	/// creates a new HashHeader by given values/hashes.
	pub fn new(version: u8, hash_header: HashHeader, number_of_chunks: u64) -> FileFooter {
		Self {
			version: version,
			hash_header: hash_header,
			number_of_chunks: number_of_chunks,
		}
	}
}

impl HeaderCoding for FileFooter {
	type Item = FileFooter;
	fn version(&self) -> u8 { 
		self.version
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_FILE_FOOTER
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(self.version);
		vec.append(&mut self.hash_header.encode_directly());
		vec.append(&mut self.number_of_chunks.encode_directly());
		vec
	}
	fn decode_content(data: Vec<u8>) -> Result<FileFooter> {
		let mut cursor = Cursor::new(data);
		let footer_version = u8::decode_directly(&mut cursor)?;
		let hash_header = HashHeader::decode_directly(&mut cursor)?;
		let number_of_chunks = u64::decode_directly(&mut cursor)?;
		Ok(FileFooter::new(footer_version, hash_header, number_of_chunks))
	}
}