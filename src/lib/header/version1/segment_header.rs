// - STD
use std::cmp::{PartialEq};
use std::io::{Cursor};

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	HEADER_IDENTIFIER_SEGMENT_HEADER,
};

/// The segment header contains all informations about the specific segment. Each segment has his own segment header.\
/// This header is **not** a part of the main header.\
#[derive(Debug,Clone,Eq)]
pub struct SegmentHeader {
	version: u8,
	unique_identifier: i64,
	segment_number: u64,
	length_of_segment: u64,
	footer_offset: u64,
}

impl SegmentHeader {
	/// returns a new empty segment header
	pub fn new_empty(version: u8, unique_identifier: i64, segment_number: u64) -> SegmentHeader {
		Self {
			version: version,
			unique_identifier: unique_identifier,
			segment_number: segment_number,
			length_of_segment: 0,
			footer_offset: 0,
		}
	}
	/// returns a new segment header with the given values.
	pub fn new(version: u8, unique_identifier: i64, segment_number: u64, length_of_segment: u64, footer_offset: u64) -> SegmentHeader {
		Self {
			version: version,
			unique_identifier: unique_identifier,
			segment_number: segment_number,
			length_of_segment: length_of_segment,
			footer_offset: footer_offset,
		}
	}

	/// returns the unique identifier of image (each segment should have the same identifier).
	pub fn unique_identifier(&self) -> i64 {
		self.unique_identifier
	}

	/// returns the segment number.
	pub fn segment_number(&self) -> u64 {
		self.segment_number
	}

	/// returns the length of the segment in bytes.
	pub fn length_of_segment(&self) -> u64 {
		self.length_of_segment
	}

	/// overwrites the length value in the header with the given value. This can be useful, if you create an 'empty'
	/// header (with length=0) and want to set the length value after reading the data from source to buffer.
	pub fn set_length_of_segment(&mut self, value: u64) {
		self.length_of_segment = value
	}

	/// sets the segment number to the next number. This can be useful, for example,
	/// if you clone a segment header from the previous one or something like that.
	pub fn next_header(&self) -> SegmentHeader {
		SegmentHeader {
			version: self.version,
			unique_identifier: self.unique_identifier,
			segment_number: self.segment_number+1,
			length_of_segment: 0,
			footer_offset: 0,
		}
	}

	/// sets the offset of the segment footer.
	pub fn set_footer_offset(&mut self, offset: u64) {
		self.footer_offset = offset
	}

	/// returns the footer offset.
	pub fn footer_offset(&self) -> u64 {
		self.footer_offset
	}
}

impl HeaderCoding for SegmentHeader {
	type Item = SegmentHeader;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_SEGMENT_HEADER
	}

	fn version(&self) -> u8 {
		self.version
	}
	
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.append(&mut self.version.encode_directly());
		vec.append(&mut self.unique_identifier.encode_directly());
		vec.append(&mut self.segment_number.encode_directly());
		vec.append(&mut self.length_of_segment.encode_directly());
		vec.append(&mut self.footer_offset.encode_directly());

		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<SegmentHeader> {
		let mut cursor = Cursor::new(data);

		let version = u8::decode_directly(&mut cursor)?;
		let unique_identifier = i64::decode_directly(&mut cursor)?;
		let segment_number = u64::decode_directly(&mut cursor)?;
		let length = u64::decode_directly(&mut cursor)?;
		let footer_offset = u64::decode_directly(&mut cursor)?;
		Ok(SegmentHeader::new(version, unique_identifier, segment_number, length, footer_offset))
	}
}

impl PartialEq for SegmentHeader {
    fn eq(&self, other: &Self) -> bool {
        self.segment_number == other.segment_number
    }
}