// - internal
use crate::{
	EncryptionAlgorithm,
	HeaderObject,
	HeaderEncoder,
	ValueEncoder,
	header::PBEHeader,
};

use crate::{
	HEADER_IDENTIFIER_ENCRYPTION_HEADER,
};

/// The encryption header contains all informations (and the **encrypted** key) for the data and header encryption.\
/// The encryption header is the only optional header part of the main header and has following layout:
/// 
/// |          | Magic bytes    | Header length  | header version | pbe header    | algorithm | encrypted<br>encryption<br>key | encryption key<br>nonce |
/// |----------|----------------|----------------|---------------|-----------|--------------------------------|-------------------------|
/// | **size** | 4 bytes        | 8 bytes        | 1 byte         | variable      | 1 byte    | variable                       | 12 byte                 |
/// | **type** | 0x7A666665     | uint64         | uint8          | header object | uint8     | Bytes                          | Bytes                   |
#[derive(Debug,Clone)]
pub struct EncryptionHeader {
	header_version: u8,
	pbe_header: PBEHeader,
	algorithm: EncryptionAlgorithm,
	encrypted_encryption_key: Vec<u8>,
	encrypted_header_nonce: [u8; 12],
}

impl EncryptionHeader {
	/// creates a new encryption header by the given values.
	pub fn new(
		header_version: u8,
		pbe_header: PBEHeader,
		algorithm: EncryptionAlgorithm,
		encrypted_encryption_key: Vec<u8>, //encrypted with set password
		encrypted_header_nonce: [u8; 12], //used for header encryption
		) -> EncryptionHeader {
		Self {
			header_version: header_version,
			pbe_header: pbe_header,
			algorithm: algorithm,
			encrypted_encryption_key: encrypted_encryption_key,
			encrypted_header_nonce: encrypted_header_nonce
		}
	}

	/// returns the used encryption algorithm.
	pub fn algorithm(&self) -> &EncryptionAlgorithm {
		&self.algorithm
	}

	/// returns the nonce/iv, used for the header encryption.
	pub fn encrypted_header_nonce(&self) -> [u8; 12] {
		self.encrypted_header_nonce
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
		vec.push(self.algorithm.clone() as u8);
		vec.append(&mut self.encrypted_encryption_key.encode_directly());
		vec.append(&mut self.encrypted_header_nonce.encode_directly());
		vec
	}
}

impl HeaderEncoder for EncryptionHeader {}