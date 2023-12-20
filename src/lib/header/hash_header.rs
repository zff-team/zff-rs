// - STD
use std::io::{Cursor, Read};
use std::fmt;

#[cfg(feature = "serde")]
use std::collections::HashMap;

// - internal
use crate::{
	Result,
	ValueEncoder,
	ValueDecoder,
	HeaderCoding,
	HashType,
	ZffError,
	HEADER_IDENTIFIER_HASH_HEADER,
	HEADER_IDENTIFIER_HASH_VALUE,
	ERROR_HEADER_DECODER_UNKNOWN_HASH_TYPE,
};

// - external
use ed25519_dalek::SIGNATURE_LENGTH;
#[cfg(feature = "serde")]
use serde::{
	Serialize,
	ser::{Serializer, SerializeStruct},
};
#[cfg(feature = "serde")]
use base64::{Engine, engine::general_purpose::STANDARD as base64engine};
#[cfg(feature = "serde")]
use hex;

/// Header for the hash values of the dumped data stream.
/// This header is part of various footers and contains 0 or more hash values of the dumped data.\
#[derive(Debug,Clone,Eq,PartialEq)]
pub struct HashHeader {
	version: u8,
	hashes: Vec<HashValue>,
}

#[cfg(feature = "serde")]
impl Serialize for HashHeader {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct(self.struct_name(), 3)?;
        state.serialize_field("version", &self.version)?;
        let mut hashes = HashMap::new();
        for hashvalue in &self.hashes {
        	hashes.insert(hashvalue.hash_type.to_string(), hashvalue);
        }
        state.serialize_field("hash", &hashes)?;
        state.end()
    }
}

impl HashHeader {
	/// creates a new HashHeader by given values/hashes.
	pub fn new(version: u8, hashes: Vec<HashValue>) -> HashHeader {
		Self {
			version,
			hashes,
		}
	}

	/// returns a reference to the underlying [HashValue]s.
	pub fn hash_values(&self) -> &Vec<HashValue> {
		&self.hashes
	}
}

impl HeaderCoding for HashHeader {
	type Item = HashHeader;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_HASH_HEADER
	}

	fn version(&self) -> u8 {
		self.version
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.version.encode_directly());
		vec.append(&mut self.hashes.encode_directly());

		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<HashHeader> {
		let mut cursor = Cursor::new(data);
		let header_version = u8::decode_directly(&mut cursor)?;
		let hashes = Vec::<HashValue>::decode_directly(&mut cursor)?;
		Ok(HashHeader::new(header_version, hashes))
	}
}

// - implement fmt::Display
impl fmt::Display for HashHeader {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl HashHeader {
	fn struct_name(&self) -> &'static str {
		"HashHeader"
	}
}

/// This is a part of the [HashHeader].
/// The HashValue-struct contains the appropriate hash algorithm and the hash. This struct has a version also.
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct HashValue {
	version: u8,
	hash_type: HashType,
	hash: Vec<u8>,
	ed25519_signature: Option<[u8; SIGNATURE_LENGTH]>,
}

impl HashValue {
	/// creates a new [HashValue] with the given parameters.
	pub fn new(version: u8, hash_type: HashType, hash: Vec<u8>, ed25519_signature: Option<[u8; SIGNATURE_LENGTH]>,) -> HashValue{
		Self {
			version,
			hash_type,
			hash,
			ed25519_signature,
		}
	}
	/// creates a new, empty [HashValue] for a given hashtype.
	pub fn new_empty(structure_version: u8, hash_type: HashType) -> HashValue {
		let hash_default_len = hash_type.default_len();
		Self {
			version: structure_version,
			hash_type,
			hash: vec!(0u8; hash_default_len/8),
			ed25519_signature: None
		}
	}

	/// returns the type of hash as [HashType](crate::hashing::HashType).
	pub fn hash_type(&self) -> &HashType {
		&self.hash_type
	}

	/// sets the hash value.
	pub fn set_hash(&mut self, hash: Vec<u8>) {
		self.hash = hash
	}

	/// returns the underlying hash value
	pub fn hash(&self) -> &Vec<u8> {
		&self.hash
	}

	/// sets the appropriate ed25519 signature
	pub fn set_ed25519_signature(&mut self, signature: [u8; SIGNATURE_LENGTH]) {
		self.ed25519_signature = Some(signature)
	}

	/// returns the appropriate signature
	pub fn ed25519_signature(&self) -> Option<[u8; SIGNATURE_LENGTH]> {
		self.ed25519_signature
	}
}


impl HeaderCoding for HashValue {
	type Item = HashValue;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_HASH_VALUE
	}

	fn version(&self) -> u8 {
		self.version
	}
	
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.version.encode_directly());
		vec.push(self.hash_type.clone() as u8);
		vec.append(&mut self.hash.encode_directly());
		match self.ed25519_signature {
			None => (),
			Some(signature) => vec.append(&mut signature.encode_directly()),
		};
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<HashValue> {
		let mut cursor = Cursor::new(&data);
		let structure_version = u8::decode_directly(&mut cursor)?;
		let hash_type = match u8::decode_directly(&mut cursor)? {
			0 => HashType::Blake2b512,
			1 => HashType::SHA256,
			2 => HashType::SHA512,
			3 => HashType::SHA3_256,
			4 => HashType::Blake3,
			_ => return Err(ZffError::new_header_decode_error(ERROR_HEADER_DECODER_UNKNOWN_HASH_TYPE)),
		};
	 	let hash = Vec::<u8>::decode_directly(&mut cursor)?;
	 	
	 	let mut ed25519_signature = None;
		if cursor.position() < (data.len() as u64 - 1) {
			let mut buffer = [0; SIGNATURE_LENGTH];
			cursor.read_exact(&mut buffer)?;
			ed25519_signature = Some(buffer);
		}

		Ok(HashValue::new(structure_version, hash_type, hash, ed25519_signature))
	}
}

// - implement fmt::Display
impl fmt::Display for HashValue {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl HashValue {
	fn struct_name(&self) -> &'static str {
		"HashValue"
	}
}

#[cfg(feature = "serde")]
impl Serialize for HashValue {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct(self.struct_name(), 3)?;
        state.serialize_field("hash_type", &self.hash_type.to_string())?;
        state.serialize_field("hash", &hex::encode(&self.hash))?;
        if let Some(signature) = &self.ed25519_signature {
        	state.serialize_field("ed25519_signature", &base64engine.encode(signature))?;
        }
        state.end()
    }
}