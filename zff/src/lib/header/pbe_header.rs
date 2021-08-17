// - internal
use crate::{
	HeaderObject,
	HeaderEncoder,
	ValueType,
};

use crate::{
	HEADER_IDENTIFIER_PBE_HEADER,
	PBE_KDF_PARAMETERS,
};

#[derive(Debug,Clone)]
pub struct PBEHeader {
	header_version: u8,
	kdf_scheme: KDFScheme,
	encryption_scheme: PBEScheme,
	kdf_parameters: KDFParameters,
	pbencryption_nonce: [u8; 16],
}

impl PBEHeader {
	pub fn new(
		header_version: u8,
		kdf_scheme: KDFScheme,
		encryption_scheme: PBEScheme,
		kdf_parameters: KDFParameters,
		pbencryption_nonce: [u8; 16],
		) -> PBEHeader {
		Self {
			header_version: header_version,
			kdf_scheme: kdf_scheme,
			encryption_scheme: encryption_scheme,
			kdf_parameters: kdf_parameters,
			pbencryption_nonce: pbencryption_nonce,
		}
	}
}

impl HeaderObject for PBEHeader {
	fn identifier() -> u32 {
		HEADER_IDENTIFIER_PBE_HEADER
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.push(self.header_version);
		vec.push(self.kdf_scheme.clone() as u8);
		vec.push(self.encryption_scheme.clone() as u8);
		vec.append(&mut self.kdf_parameters.encode_directly());
		vec.append(&mut self.pbencryption_nonce.encode_directly());
		vec
	}
}

impl HeaderEncoder for PBEHeader {
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

#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone)]
pub enum KDFScheme {
	PBKDF2SHA256 = 0,
}

#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone)]
pub enum PBEScheme {
	AES128CBC = 0,
	AES256CBC = 1,
}

#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone)]
pub enum KDFParameters {
	PBKDF2SHA256Parameters(PBKDF2SHA256Parameters),
}

impl HeaderEncoder for KDFParameters {
	fn encode_directly(&self) -> Vec<u8> {
		match self {
			KDFParameters::PBKDF2SHA256Parameters(params) => params.encode_directly(),
		}
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
pub struct PBKDF2SHA256Parameters {
	iterations: u16,
	salt: [u8; 32],
}

impl HeaderObject for PBKDF2SHA256Parameters {
	fn identifier() -> u32 {
		PBE_KDF_PARAMETERS
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.iterations.encode_directly());
		vec.append(&mut self.salt.encode_directly());
		vec
	}
}

impl HeaderEncoder for PBKDF2SHA256Parameters {
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