// - STD
use std::io::{Cursor};

// - internal
use crate::{
	Result,
	HeaderEncoder,
	HeaderDecoder,
	ValueEncoder,
	ValueDecoder,
	HeaderObject,
	HashType,
	ZffError,
	HEADER_IDENTIFIER_HASH_HEADER,
	HEADER_IDENTIFIER_HASH_VALUE,
	ERROR_HEADER_DECODER_UNKNOWN_HASH_TYPE,
};

// - external
use serde::ser::{Serialize, Serializer, SerializeStruct};
use hex::ToHex;

/// Header for the hash values of the dumped data stream.
/// This header is part of the main header and contains 0 or more hash values of the dumped data.\
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

	pub fn hash_values(&self) -> &Vec<HashValue> {
		&self.hashes
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

impl HeaderDecoder for HashHeader {
	type Item = HashHeader;

	fn decode_content(data: Vec<u8>) -> Result<HashHeader> {
		let mut cursor = Cursor::new(data);
		let header_version = u8::decode_directly(&mut cursor)?;
		let hashes = Vec::<HashValue>::decode_directly(&mut cursor)?;
		Ok(HashHeader::new(header_version, hashes))
	}
}

impl Serialize for HashHeader {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("HashHeader", 3)?;
        state.serialize_field("header_version", &self.header_version)?;
        state.serialize_field("hash_value", &self.hashes)?;
        state.end()
    }
}

/// This is a part of the [HashHeader](struct.HashHeader.html).
/// The HashValue-struct contains the appropriate hash algorithm and the hash. This struct has a version also.
#[derive(Debug,Clone)]
pub struct HashValue {
	structure_version: u8,
	hash_type: HashType,
	hash: Vec<u8>,
}

impl HashValue {
	/// creates a new [HashValue](struct.HashValue.html) for the given parameters.
	pub fn new(structure_version: u8, hash_type: HashType, hash: Vec<u8>) -> HashValue{
		Self {
			structure_version: structure_version,
			hash_type: hash_type,
			hash: hash
		}
	}
	/// creates a new, empty [HashValue](struct.HashValue.html) for a given hashtype.
	pub fn new_empty(structure_version: u8, hash_type: HashType) -> HashValue {
		let hash_default_len = hash_type.default_len();
		Self {
			structure_version: structure_version,
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
		vec.push(self.structure_version);
		vec.push(self.hash_type.clone() as u8);
		vec.append(&mut self.hash.encode_directly());

		vec
	}
}

impl HeaderEncoder for HashValue {}

impl HeaderDecoder for HashValue {
	type Item = HashValue;

	fn decode_content(data: Vec<u8>) -> Result<HashValue> {
		let mut cursor = Cursor::new(data);
		let structure_version = u8::decode_directly(&mut cursor)?;
		let hash_type = match u8::decode_directly(&mut cursor)? {
			0 => HashType::Blake2b512,
			1 => HashType::SHA256,
			2 => HashType::SHA512,
			3 => HashType::SHA3_256,
			_ => return Err(ZffError::new_header_decode_error(ERROR_HEADER_DECODER_UNKNOWN_HASH_TYPE)),
		};
	 let hash = Vec::<u8>::decode_directly(&mut cursor)?;
		Ok(HashValue::new(structure_version, hash_type, hash))
	}
}

impl Serialize for HashValue {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("HashValue", 3)?;
        state.serialize_field("structure_version", &self.structure_version)?;
        state.serialize_field("hash_type", &self.hash_type)?;
        state.serialize_field("hash", &self.hash.encode_hex::<String>())?;
        state.end()
    }
}