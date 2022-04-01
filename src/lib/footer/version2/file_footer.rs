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
use crate::header::{
	HashHeader,
};

/// The file footer is written at the end of each acquired file.
/// The file footer contains several metadata about the acquisition process itself: e.g. the acquisition start/end time of the appropriate file,
/// hash values, or size information.
/// The general structure of the file footer is the same for all file types.
#[derive(Debug,Clone,Eq,PartialEq)]
pub struct FileFooter {
	version: u8,
	acquisition_start: u64,
	acquisition_end: u64,
	hash_header: HashHeader,
	first_chunk_number: u64,
	number_of_chunks: u64,
	length_of_data: u64,
}

impl FileFooter {
	/// creates a new FileFooter by given values/hashes.
	pub fn new(version: u8, acquisition_start: u64, acquisition_end: u64, hash_header: HashHeader, first_chunk_number: u64, number_of_chunks: u64, length_of_data: u64) -> FileFooter {
		Self {
			version,
			acquisition_start,
			acquisition_end,
			hash_header,
			first_chunk_number,
			number_of_chunks,
			length_of_data,
		}
	}

	/// returns the acquisition start time.
	pub fn acquisition_start(&self) -> u64 {
		self.acquisition_start
	}

	/// returns the acquisition end time.
	pub fn acquisition_end(&self) -> u64 {
		self.acquisition_end
	}

	/// returns the hash header.
	pub fn hash_header(&self) -> &HashHeader {
		&self.hash_header
	}

	/// returns the first chunk number, used for the underlying file.
	pub fn first_chunk_number(&self) -> u64 {
		self.first_chunk_number
	}

	/// returns the total number of chunks, used for the underlying file.
	pub fn number_of_chunks(&self) -> u64 {
		self.number_of_chunks
	}

	/// if the file is a regular file, this method returns the original (uncompressed, unencrypted) size of the file (without "filesystem-"metadata - just the size of the file content).
	/// if the file is a hardlink, this method returns the size of the inner value (just the size of the appropriate filenumber: 8).
	/// if the file is a directory, this method returns the size of the underlying vector of childs.
	/// if the file is a symlink, this method returns the length of the linked path.
	pub fn length_of_data(&self) -> u64 {
		self.length_of_data
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
		let mut vec = vec![self.version];
		vec.append(&mut self.acquisition_start.encode_directly());
		vec.append(&mut self.acquisition_end.encode_directly());
		vec.append(&mut self.hash_header.encode_directly());
		vec.append(&mut self.first_chunk_number.encode_directly());
		vec.append(&mut self.number_of_chunks.encode_directly());
		vec.append(&mut self.length_of_data.encode_directly());
		vec
	}
	fn decode_content(data: Vec<u8>) -> Result<FileFooter> {
		let mut cursor = Cursor::new(data);
		let footer_version = u8::decode_directly(&mut cursor)?;
		let acquisition_start = u64::decode_directly(&mut cursor)?;
		let acquisition_end = u64::decode_directly(&mut cursor)?;
		let hash_header = HashHeader::decode_directly(&mut cursor)?;
		let first_chunk_number = u64::decode_directly(&mut cursor)?;
		let number_of_chunks = u64::decode_directly(&mut cursor)?;
		let length_of_data = u64::decode_directly(&mut cursor)?;
		Ok(FileFooter::new(footer_version, acquisition_start, acquisition_end, hash_header, first_chunk_number, number_of_chunks, length_of_data))
	}
}