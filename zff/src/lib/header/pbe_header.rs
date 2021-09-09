// - internal
use crate::{
	HeaderObject,
	HeaderEncoder,
	KDFScheme,
	PBEScheme,
};

use crate::{
	HEADER_IDENTIFIER_PBE_HEADER,
	PBE_KDF_PARAMETERS,
};

/// The pbe header contains all informations for the encryption of the encryption key.\
/// The encryption key, used for the chunk encryption, can be found at the [EncryptionHeader](struct.EncryptionHeader.html) -
/// encrypted with an user password.\
/// This encryption of the encryption key is done via a password-based encryption (PBE).\
/// All metadata about this PBE can be found in this PBEHeader.\
/// The PBEHeader has the following layout:
///
/// |          | Magic bytes | Header length | header<br>version | KDF flag | encryption<br>scheme<br>flag | KDF<br>parameters | PBEncryption<br>Nonce/IV |
/// |----------|-------------|---------------|-------------------|----------|------------------------------|-------------------|--------------------------|
/// | **size** | 4 bytes     | 8 bytes       | 1 byte            | 1 bytes  | 1 byte                       | variable          | 16 bytes                 |
/// | **type** | 0x7A666670  | uint64        | uint8             | uint8    | uint8                        | [KDFParameters]   | Bytes                    |
#[derive(Debug,Clone)]
pub struct PBEHeader {
	header_version: u8,
	kdf_scheme: KDFScheme,
	encryption_scheme: PBEScheme,
	kdf_parameters: KDFParameters,
	pbencryption_nonce: [u8; 16],
}

impl PBEHeader {
	/// returns a new pbe header with the given values.
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
		vec.append(&mut self.encode_directly());
		vec
	}
}

/// enum to handle the stored parameters for the appropriate key deriavation function (KDF).
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone)]
pub enum KDFParameters {
	/// stores a struct [PBKDF2SHA256Parameters].
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
		vec.append(&mut self.encode_directly());
		vec
	}
}

/// struct to store the parameters for the KDF PBKDF2-SHA256.
#[derive(Debug,Clone)]
pub struct PBKDF2SHA256Parameters {
	iterations: u16,
	salt: [u8; 32],
}

impl PBKDF2SHA256Parameters {
	/// returns a new [PBKDF2SHA256Parameters] with the given values.
	pub fn new(iterations: u16, salt: [u8; 32]) -> PBKDF2SHA256Parameters {
		Self {
			iterations: iterations,
			salt: salt,
		}
	}
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
		vec.append(&mut self.encode_directly());
		vec
	}
}