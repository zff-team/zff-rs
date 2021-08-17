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