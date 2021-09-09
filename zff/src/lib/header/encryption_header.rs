// - internal
use crate::{
	EncryptionAlgorithm,
	HeaderObject,
	HeaderEncoder,
	PBEHeader,
};

use crate::{
	HEADER_IDENTIFIER_ENCRYPTION_HEADER,
};

#[derive(Debug,Clone)]
pub struct EncryptionHeader {
	header_version: u8,
	pbe_header: PBEHeader,
	encryption_algorithm: EncryptionAlgorithm,
	encrypted_encryption_key: Vec<u8>,
	encryption_key_nonce: [u8; 12],
}

impl EncryptionHeader {
	pub fn new(
		header_version: u8,
		pbe_header: PBEHeader,
		encryption_algorithm: EncryptionAlgorithm,
		encrypted_encryption_key: Vec<u8>, //encrypted with set password
		encryption_key_nonce: [u8; 12], //used for header encryption
		) -> EncryptionHeader {
		Self {
			header_version: header_version,
			pbe_header: pbe_header,
			encryption_algorithm: encryption_algorithm,
			encrypted_encryption_key: encrypted_encryption_key,
			encryption_key_nonce: encryption_key_nonce
		}
	}

	pub fn encryption_algorithm(&self) -> &EncryptionAlgorithm {
		&self.encryption_algorithm
	}

	pub fn encryption_key_nonce(&self) -> [u8; 12] {
		self.encryption_key_nonce
	}
}

impl HeaderObject for EncryptionHeader {
	fn identifier() -> u32 {
		HEADER_IDENTIFIER_ENCRYPTION_HEADER
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.push(self.header_version);
		vec.append(&mut self.pbe_header.encode_directly());
		vec.push(self.encryption_algorithm.clone() as u8);
		vec.append(&mut self.encrypted_encryption_key.encode_directly());
		vec.append(&mut self.encryption_key_nonce.encode_directly());
		vec
	}
}

impl HeaderEncoder for EncryptionHeader {
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