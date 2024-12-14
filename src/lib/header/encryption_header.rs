// - STD
use std::io::{Cursor, Read};
use std::fmt;

// - internal
use crate::{
	Result,
	EncryptionAlgorithm,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	header::{PBEHeader, KDFParameters, ObjectHeader},
	ZffError,
	ZffErrorKind,
	KDFScheme,
	PBEScheme,
	encryption::*,
};

use crate::{
	HEADER_IDENTIFIER_ENCRYPTION_HEADER,
	ERROR_HEADER_DECODER_UNKNOWN_ENCRYPTION_ALGORITHM,
	DEFAULT_HEADER_VERSION_ENCRYPTION_HEADER,
};

// - external
#[cfg(feature = "serde")]
use serde::{
	Deserialize,
	Serialize,
};

/// This struct could be used to manage the encryption information while creating a zff container
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct EncryptionInformation {
	/// The encryption key in **unencrypted** form.
	#[cfg_attr(feature = "serde", serde(serialize_with = "crate::helper::buffer_to_hex", deserialize_with = "crate::helper::hex_to_buffer"))]
	pub encryption_key: Vec<u8>,
	/// The used [crate::encryption::EncryptionAlgorithm].
	pub algorithm: EncryptionAlgorithm,
}

impl EncryptionInformation {
	/// Creates a new [EncryptionInformation] by the given values.
	pub fn new(key: Vec<u8>, algorithm: EncryptionAlgorithm) -> Self {
		Self {
			encryption_key: key,
			algorithm
		}
	}
}

impl TryFrom<ObjectHeader> for EncryptionInformation {
	type Error = ZffError;
	fn try_from(obj_header: ObjectHeader) -> Result<Self> {
		match obj_header.encryption_header {
			None => Err(ZffError::new(ZffErrorKind::MissingEncryptionHeader, "")),
			Some(enc_header) => {
				match enc_header.get_encryption_key() {
					None => Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, "")),
					Some(key) => Ok(EncryptionInformation {
						encryption_key: key,
						algorithm: enc_header.algorithm
					}),
				}
			}
		}
	}
}

impl TryFrom<&ObjectHeader> for EncryptionInformation {
	type Error = ZffError;
	fn try_from(obj_header: &ObjectHeader) -> Result<Self> {
		match obj_header.encryption_header {
			None => Err(ZffError::new(ZffErrorKind::MissingEncryptionHeader, "")),
			Some(ref enc_header) => {
				match enc_header.get_encryption_key() {
					None => Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, "")),
					Some(key) => Ok(EncryptionInformation {
						encryption_key: key,
						algorithm: enc_header.algorithm.clone()
					}),
				}
			}
		}
	}
}

// - implement fmt::Display
impl fmt::Display for EncryptionInformation {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl EncryptionInformation {
	fn struct_name(&self) -> &'static str {
		"EncryptionInformation"
	}
}

/// The encryption header contains all informations (and the **encrypted** key) for the data and header encryption.
/// 
/// The encryption header is the only optional header part of the main header
/// (With the exception of the [PBEHeader], which is, however, part of the [EncryptionHeader]).
/// The encryption header contains an encrypted key (encrypted encryption key). This key is encrypted with a password based encryption method,
/// described by the containing [PBEHeader].
/// This key (decrypted with the appropriate password) is used to decrypt the encrypted data or the optionally encrypted header.
#[derive(Debug,Clone,Eq,PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct EncryptionHeader {
	/// The password based encryption header.
	pub pbe_header: PBEHeader,
	/// The used encryption algorithm.
	pub algorithm: EncryptionAlgorithm,
	/// The encrypted encryption key.
	#[cfg_attr(feature = "serde", serde(serialize_with = "crate::helper::buffer_to_base64", deserialize_with = "crate::helper::base64_to_buffer"))]
	pub encrypted_encryption_key: Vec<u8>,
	/// The decrypted encryption key.
	#[cfg_attr(feature = "serde", serde(serialize_with = "crate::helper::option_buffer_to_base64"))]
	pub decrypted_encryption_key: Option<Vec<u8>>
}

impl EncryptionHeader {
	/// creates a new encryption header by the given values.
	pub fn new(
		pbe_header: PBEHeader,
		algorithm: EncryptionAlgorithm,
		encrypted_encryption_key: Vec<u8>, //encrypted with set password
		) -> EncryptionHeader {
		Self {
			pbe_header,
			algorithm,
			encrypted_encryption_key,
			decrypted_encryption_key: None,
		}
	}

	/// returns the decrypted encryption key. If the Key is already encrypted, you will get an None and should use the decrypt_encryption_key() method.
	pub fn get_encryption_key(&self) -> Option<Vec<u8>> {
		self.decrypted_encryption_key.clone()
	}

	/// returns the decrypted encryption key. If the Key is already encrypted, you will get an None and should use the decrypt_encryption_key() method.
	pub fn get_encryption_key_ref(&self) -> Option<&Vec<u8>> {
		self.decrypted_encryption_key.as_ref()
	}

	/// tries to decrypt the encryption key.
	pub fn decrypt_encryption_key<P: AsRef<[u8]>>(&mut self, password: P) -> Result<Vec<u8>> {
		if let Some(decrypted_encryption_key) = &self.decrypted_encryption_key {
			return Ok(decrypted_encryption_key.clone())
		}
		let decryption_key = match self.pbe_header.kdf_scheme {
			KDFScheme::PBKDF2SHA256 => match &self.pbe_header.kdf_parameters {
				KDFParameters::PBKDF2SHA256Parameters(parameters) => {
					let iterations = parameters.iterations;
					let salt = parameters.salt;
					match self.pbe_header.encryption_scheme {
						PBEScheme::AES128CBC => decrypt_pbkdf2sha256_aes128cbc(
							iterations,
							&salt,
							&self.pbe_header.pbencryption_nonce,
							&password,
							&self.encrypted_encryption_key
							),
						PBEScheme::AES256CBC => decrypt_pbkdf2sha256_aes256cbc(
							iterations,
							&salt,
							&self.pbe_header.pbencryption_nonce,
							&password,
							&self.encrypted_encryption_key
							),
					}
				}
				_ => Err(ZffError::new(ZffErrorKind::MalformedHeader, ""))
			},
			KDFScheme::Scrypt => match &self.pbe_header.kdf_parameters {
				KDFParameters::ScryptParameters(parameters) => {
					let logn = parameters.logn;
					let p = parameters.p;
					let r = parameters.r;
					let salt = parameters.salt;
					match self.pbe_header.encryption_scheme {
						PBEScheme::AES128CBC => decrypt_scrypt_aes128cbc(
							logn,
							p,
							r,
							&salt,
							&self.pbe_header.pbencryption_nonce,
							&password,
							&self.encrypted_encryption_key
							),
						PBEScheme::AES256CBC => decrypt_scrypt_aes256cbc(
							logn,
							p,
							r,
							&salt,
							&self.pbe_header.pbencryption_nonce,
							&password,
							&self.encrypted_encryption_key
							),
					}
				},
				_ => Err(ZffError::new(ZffErrorKind::MalformedHeader, "")),
			},
			KDFScheme::Argon2id => match &self.pbe_header.kdf_parameters {
				KDFParameters::Argon2idParameters(parameters) => {
					let mem_cost = parameters.mem_cost;
					let lanes = parameters.lanes;
					let iterations = parameters.iterations;
					let salt = parameters.salt;
					match self.pbe_header.encryption_scheme {
						PBEScheme::AES128CBC => decrypt_argon2_aes128cbc(
							mem_cost,
							lanes,
							iterations,
							&salt,
							&self.pbe_header.pbencryption_nonce,
							&password,
							&self.encrypted_encryption_key
							),
						PBEScheme::AES256CBC => decrypt_argon2_aes256cbc(
							mem_cost,
							lanes,
							iterations,
							&salt,
							&self.pbe_header.pbencryption_nonce,
							&password,
							&self.encrypted_encryption_key
							),
					}
				},
				_ => Err(ZffError::new(ZffErrorKind::MalformedHeader, "")),
			},
		}?;
		self.decrypted_encryption_key = Some(decryption_key.clone());
		Ok(decryption_key)
	}
}

impl HeaderCoding for EncryptionHeader {
	type Item = EncryptionHeader;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_ENCRYPTION_HEADER
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_ENCRYPTION_HEADER
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![Self::version()];
		vec.append(&mut self.pbe_header.encode_directly());
		vec.push(self.algorithm.clone() as u8);
		vec.append(&mut self.encrypted_encryption_key.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<EncryptionHeader> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?;
		let pbe_header = PBEHeader::decode_directly(&mut cursor)?;
		let encryption_algorithm = match u8::decode_directly(&mut cursor)? {
			0 => EncryptionAlgorithm::AES128GCM,
			1 => EncryptionAlgorithm::AES256GCM,
			2 => EncryptionAlgorithm::CHACHA20POLY1305,
			_ => return Err(ZffError::new_header_decode_error(ERROR_HEADER_DECODER_UNKNOWN_ENCRYPTION_ALGORITHM)),
		};
		let key_length = u64::decode_directly(&mut cursor)? as usize;
		let mut encryption_key = vec![0u8; key_length];
		cursor.read_exact(&mut encryption_key)?;
		Ok(EncryptionHeader::new(pbe_header, encryption_algorithm, encryption_key))
	}
}

// - implement fmt::Display
impl fmt::Display for EncryptionHeader {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl EncryptionHeader {
	fn struct_name(&self) -> &'static str {
		"EncryptionHeader"
	}
}
