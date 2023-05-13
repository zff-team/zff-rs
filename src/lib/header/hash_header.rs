// - STD
use std::io::{Cursor, Read};

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
use ed25519_dalek::{SIGNATURE_LENGTH};

/// Header for the hash values of the dumped data stream.
/// This header is part of various footers and contains 0 or more hash values of the dumped data.\
#[derive(Debug,Clone,Eq,PartialEq)]
pub struct HashHeader {
	version: u8,
	hashes: Vec<HashValue>,
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