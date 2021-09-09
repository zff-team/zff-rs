// - STD
use std::cmp::{PartialEq};

// - internal
use crate::{
	HeaderObject,
	HeaderEncoder,
	ValueType,
	HEADER_IDENTIFIER_SEGMENT_HEADER
};

#[derive(Debug,Clone,Eq)]
pub struct SegmentHeader {
	header_version: u8,
	unique_identifier: u64,
	segment_number: u64,
	length_of_segment: u64,
}

impl SegmentHeader {
	pub fn new(header_version: u8, unique_identifier: u64, segment_number: u64, length_of_segment: u64) -> SegmentHeader {
		Self {
			header_version: header_version,
			unique_identifier: unique_identifier,
			segment_number: segment_number,
			length_of_segment: length_of_segment,
		}
	}

	pub fn header_version(&self) -> u8 {
		self.header_version
	}

	pub fn unique_identifier(&self) -> u64 {
		self.unique_identifier
	}

	pub fn segment_number(&self) -> u64 {
		self.segment_number
	}

	pub fn length_of_segment(&self) -> u64 {
		self.length_of_segment
	}

	pub fn set_length_of_segment(&mut self, value: u64) {
		self.length_of_segment = value
	}

	pub fn next_header(&self) -> SegmentHeader {
		SegmentHeader {
			header_version: self.header_version,
			unique_identifier: self.unique_identifier,
			segment_number: self.segment_number+1,
			length_of_segment: 0
		}
	}
}

impl HeaderObject for SegmentHeader {
	fn identifier() -> u32 {
		HEADER_IDENTIFIER_SEGMENT_HEADER
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.append(&mut self.header_version.encode_directly());
		vec.append(&mut self.unique_identifier.encode_directly());
		vec.append(&mut self.segment_number.encode_directly());
		vec.append(&mut self.length_of_segment.encode_directly());

		vec
	}
}

impl HeaderEncoder for SegmentHeader {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_header = self.encode_header();
		let identifier = Self::identifier();
		let encoded_header_length = 4 + 8 + (encoded_header.len() as u64); //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.append(&mut encoded_header);

		vec
	}
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = Self::encode_key(key);
		vec.append(&mut encoded_key);
		vec.push(ValueType::Object.clone() as u8);
		vec.append(&mut self.encode_directly());
		vec
	}
}

impl PartialEq for SegmentHeader {
    fn eq(&self, other: &Self) -> bool {
        self.segment_number == other.segment_number
    }
}