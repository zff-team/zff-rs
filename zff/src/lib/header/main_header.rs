// - internal
use crate::{
	HeaderEncoder,
	HeaderObject,
	ValueType,
	CompressionHeader,
	DescriptionHeader,
	HEADER_IDENTIFIER_MAIN_HEADER
};

#[derive(Debug,Clone)]
pub struct MainHeader {
	header_version: u8,
	compression_header: CompressionHeader,
	description_header: DescriptionHeader,
	length_of_data: u64,
}

impl MainHeader {
	pub fn new(
		header_version: u8,
		compression_header: CompressionHeader,
		description_header: DescriptionHeader,
		length_of_data: u64) -> MainHeader {
		Self {
			header_version: header_version,
			compression_header: compression_header,
			description_header: description_header,
			length_of_data: length_of_data,
		}
	}

	pub fn header_version(&self) -> u8 {
		self.header_version
	}
}

impl HeaderObject for MainHeader {
	fn identifier() -> u32 {
		HEADER_IDENTIFIER_MAIN_HEADER
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.push(self.header_version);
		vec.append(&mut self.compression_header.encode_directly());
		vec.append(&mut self.description_header.encode_directly());
		vec.append(&mut self.length_of_data.encode_directly());

		vec
	}
}

impl HeaderEncoder for MainHeader {
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