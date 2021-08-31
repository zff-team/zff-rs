// - STD
use std::cmp::{PartialEq};

// - internal
use crate::{
	HeaderObject,
	HeaderEncoder,
	ValueType,
	HEADER_IDENTIFIER_SPLIT_HEADER
};

#[derive(Debug,Clone,Eq)]
pub struct SplitHeader {
	header_version: u8,
	unique_identifier: u64,
	split_number: u64,
	length_of_split: u64,
}

impl SplitHeader {
	pub fn new(header_version: u8, unique_identifier: u64, split_number: u64, length_of_split: u64) -> SplitHeader {
		Self {
			header_version: header_version,
			unique_identifier: unique_identifier,
			split_number: split_number,
			length_of_split: length_of_split,
		}
	}

	pub fn header_version(&self) -> u8 {
		self.header_version
	}

	pub fn unique_identifier(&self) -> u64 {
		self.unique_identifier
	}

	pub fn split_number(&self) -> u64 {
		self.split_number
	}

	pub fn length_of_split(&self) -> u64 {
		self.length_of_split
	}

	pub fn set_length_of_split(&mut self, value: u64) {
		self.length_of_split = value
	}

	pub fn next_header(&self) -> SplitHeader {
		SplitHeader {
			header_version: self.header_version,
			unique_identifier: self.unique_identifier,
			split_number: self.split_number+1,
			length_of_split: 0
		}
	}
}

impl HeaderObject for SplitHeader {
	fn identifier() -> u32 {
		HEADER_IDENTIFIER_SPLIT_HEADER
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.append(&mut self.header_version.encode_directly());
		vec.append(&mut self.unique_identifier.encode_directly());
		vec.append(&mut self.split_number.encode_directly());
		vec.append(&mut self.length_of_split.encode_directly());

		vec
	}
}

impl HeaderEncoder for SplitHeader {
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

impl PartialEq for SplitHeader {
    fn eq(&self, other: &Self) -> bool {
        self.split_number == other.split_number
    }
}