// - internal
use crate::{
	HeaderEncoder,
	HeaderObject,
	ValueType,
	HashType,
	HEADER_IDENTIFIER_HASH_HEADER,
	HEADER_IDENTIFIER_HASH_VALUE,
};

#[derive(Debug,Clone)]
pub struct HashHeader {
	header_version: u8,
	hashes: Vec<HashValue>,
}

impl HashHeader {
	pub fn new(header_version: u8, hashes: Vec<HashValue>) -> HashHeader {
		Self {
			header_version: header_version,
			hashes: hashes,
		}
	}
}

impl HeaderObject for HashHeader {
	fn identifier() -> u32 {
		HEADER_IDENTIFIER_HASH_HEADER
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.push(self.header_version);
		vec.append(&mut self.hashes.encode_directly());

		vec
	}
}

impl HeaderEncoder for HashHeader {
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



#[derive(Debug,Clone)]
pub struct HashValue {
	header_version: u8,
	hash_type: HashType,
	hash: Vec<u8>,
}

impl HashValue {
	pub fn new_empty(header_version: u8, hash_type: HashType) -> HashValue {
		let hash_default_len = hash_type.default_len();
		Self {
			header_version: header_version,
			hash_type: hash_type,
			hash: vec!(0u8; hash_default_len),
		}
	}

	pub fn hash_type(&self) -> &HashType {
		&self.hash_type
	}

	pub fn set_hash(&mut self, hash: Vec<u8>) {
		self.hash = hash
	}
}

impl HeaderObject for HashValue {
	fn identifier() -> u32 {
		HEADER_IDENTIFIER_HASH_VALUE
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(self.header_version);
		vec.push(self.hash_type.clone() as u8);
		vec.append(&mut self.hash.encode_directly());

		vec
	}
}

impl HeaderEncoder for HashValue {
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