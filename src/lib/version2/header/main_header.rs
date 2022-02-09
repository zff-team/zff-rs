// - STD
use std::io::{Cursor};

// - internal
use crate::{
	Result,
	ValueEncoder,
	ValueDecoder,
	HeaderCoding,
	HEADER_IDENTIFIER_MAIN_HEADER,
};

/// The main header is the first Header, which can be found at the beginning of the first segment.\
/// This header contains a lot of other headers (e.g. compression header, ...) and start information.
#[derive(Debug,Clone)]
pub struct MainHeader {
	version: u8,
	chunk_size: u8,
	segment_size: u64,
	unique_identifier: i64,
}

impl MainHeader {
	/// returns a new main header with the given values.
	pub fn new(
		version: u8,
		chunk_size: u8, // the target chunk size
		segment_size: u64,
		unique_identifier: i64) -> MainHeader {
		Self {
			version: version,
			chunk_size: chunk_size,
			segment_size: segment_size,
			unique_identifier: unique_identifier,
		}
	}

	/// returns the chunk_size.
	pub fn chunk_size(&self) -> usize {
		1<<self.chunk_size
	}

	/// returns the segment size
	pub fn segment_size(&self) -> u64 {
		match &self.segment_size {
			0 => u64::MAX,
			_ => self.segment_size
		}
	}

	/// returns the len() of the ```Vec<u8>``` (encoded main header).
	pub fn get_encoded_size(&self) -> usize {
		self.encode_directly().len()
	}

	/// returns the unique identifier
	pub fn unique_identifier(&self) -> i64 {
		self.unique_identifier
	}
}

impl HeaderCoding for MainHeader {
	type Item = MainHeader;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_MAIN_HEADER
	}

	fn version(&self) -> u8 {
		self.version
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.push(self.version);
		vec.push(self.chunk_size);
		vec.append(&mut self.segment_size.encode_directly());
		vec.append(&mut self.unique_identifier.encode_directly());
		vec
	}
	
	fn decode_content(data: Vec<u8>) -> Result<MainHeader> {
		let mut cursor = Cursor::new(&data);
		let version = u8::decode_directly(&mut cursor)?;
		let chunk_size = u8::decode_directly(&mut cursor)?;
		let segment_size = u64::decode_directly(&mut cursor)?;
		let unique_identifier = i64::decode_directly(&mut cursor)?;


		Ok(MainHeader::new(version, chunk_size, segment_size, unique_identifier))
	}
}