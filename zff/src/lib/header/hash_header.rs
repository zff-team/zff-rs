// - internal
use crate::{
	HeaderEncoder,
	HeaderObject,
	HashType,
	HEADER_IDENTIFIER_HASH_HEADER,
	HEADER_IDENTIFIER_HASH_VALUE,
};

/// Header for the hash values of the dumped data stream.
/// This header is part of the main header and contains 0 or more hash values of the dumped data.\
/// The header has following layout:
/// 
/// |          | Magic bytes    | header length  | header version | hashes                                    |
/// |----------|----------------|----------------|----------------|-------------------------------------------|
/// | **size** | 4 bytes        | 8 bytes        | 1 byte         | variable                                  |
/// | **type** | 0x7A666668     | uint64         | uint8          | Vec\<[HashValue](struct.HashValue.html)\> |
#[derive(Debug,Clone)]
pub struct HashHeader {
	header_version: u8,
	hashes: Vec<HashValue>,
}

impl HashHeader {
	/// creates a new HashHeader by given values/hashes.
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
		vec.append(&mut self.encode_directly());
		vec
	}
}

/// This is a part of the [HashHeader](struct.HashHeader.html).
/// The HashValue-struct contains the appropriate hash algorithm and the hash. This struct has a version also.
#[derive(Debug,Clone)]
pub struct HashValue {
	header_version: u8,
	hash_type: HashType,
	hash: Vec<u8>,
}

impl HashValue {
	/// creates a new, empty [HashValue](struct.HashValue.html) for a given hashtype.
	pub fn new_empty(header_version: u8, hash_type: HashType) -> HashValue {
		let hash_default_len = hash_type.default_len();
		Self {
			header_version: header_version,
			hash_type: hash_type,
			hash: vec!(0u8; hash_default_len/8),
		}
	}

	/// returns the type of hash as [HashType](enum.HashType.html).
	pub fn hash_type(&self) -> &HashType {
		&self.hash_type
	}

	/// sets the hash value.
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
		vec.append(&mut self.encode_directly());
		vec
	}
}