// - STD
use std::io::{Cursor, Read};

// - internal
use crate::{
	Result,
	EncryptionAlgorithm,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	header::{PBEHeader, KDFParameters},
	ZffError,
	ZffErrorKind,
	KDFScheme,
	PBEScheme,
	Encryption,
};

use crate::{
	HEADER_IDENTIFIER_ENCRYPTION_HEADER,
	ERROR_HEADER_DECODER_UNKNOWN_ENCRYPTION_ALGORITHM,
};

/// This struct could be used to manage the encryption information while creating a zff container
pub struct EncryptionInformation {
	pub encryption_key: Vec<u8>,
	pub algorithm: EncryptionAlgorithm,
}

impl EncryptionInformation {
	pub fn new(key: Vec<u8>, algorithm: EncryptionAlgorithm) -> Self {
		Self {
			encryption_key: key,
			algorithm
		}
	}
}

/// The encryption header contains all informations (and the **encrypted** key) for the data and header encryption.\
/// The encryption header is the only optional header part of the main header
/// (With the exception of the [PBEHeader], which is, however, part of the [EncryptionHeader]).
/// The encryption header contains an encrypted key (encrypted encryption key). This key is encrypted with a password based encryption method,
/// described by the containing [PBEHeader].
/// This key (decrypted with the appropriate password) is used to decrypt the encrypted data or the optionally encrypted header.
#[derive(Debug,Clone,Eq,PartialEq)]
pub struct EncryptionHeader {
	version: u8,
	pbe_header: PBEHeader,
	algorithm: EncryptionAlgorithm,
	encrypted_encryption_key: Vec<u8>,
	decrypted_encryption_key: Option<Vec<u8>>
}

impl EncryptionHeader {
	/// creates a new encryption header by the given values.
	pub fn new(
		version: u8,
		pbe_header: PBEHeader,
		algorithm: EncryptionAlgorithm,
		encrypted_encryption_key: Vec<u8>, //encrypted with set password
		) -> EncryptionHeader {
		Self {
			version,
			pbe_header,
			algorithm,
			encrypted_encryption_key,
			decrypted_encryption_key: None,
		}
	}

	/// returns the used encryption algorithm as a reference.
	pub fn algorithm(&self) -> &EncryptionAlgorithm {
		&self.algorithm
	}

	/// returns a reference to the inner PBE header.
	pub fn pbe_header(&self) -> &PBEHeader {
		&self.pbe_header
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
		let decryption_key = match self.pbe_header.kdf_scheme() {
			KDFScheme::PBKDF2SHA256 => match self.pbe_header.kdf_parameters() {
				KDFParameters::PBKDF2SHA256Parameters(parameters) => {
					let iterations = parameters.iterations();
					let salt = parameters.salt();
					match self.pbe_header.encryption_scheme() {
						PBEScheme::AES128CBC => Encryption::decrypt_pbkdf2sha256_aes128cbc(
							iterations,
							salt,
							self.pbe_header.nonce(),
							&password,
							&self.encrypted_encryption_key
							),
						PBEScheme::AES256CBC => Encryption::decrypt_pbkdf2sha256_aes256cbc(
							iterations,
							salt,
							self.pbe_header.nonce(),
							&password,
							&self.encrypted_encryption_key
							),
					}
				}
				_ => Err(ZffError::new(ZffErrorKind::MalformedHeader, ""))
			},
			KDFScheme::Scrypt => match self.pbe_header.kdf_parameters() {
				KDFParameters::ScryptParameters(parameters) => {
					let logn = parameters.logn();
					let p = parameters.p();
					let r = parameters.r();
					let salt = parameters.salt();
					match self.pbe_header.encryption_scheme() {
						PBEScheme::AES128CBC => Encryption::decrypt_scrypt_aes128cbc(
							logn,
							p,
							r,
							salt,
							self.pbe_header.nonce(),
							&password,
							&self.encrypted_encryption_key
							),
						PBEScheme::AES256CBC => Encryption::decrypt_scrypt_aes256cbc(
							logn,
							p,
							r,
							salt,
							self.pbe_header.nonce(),
							&password,
							&self.encrypted_encryption_key
							),
					}
				},
				_ => Err(ZffError::new(ZffErrorKind::MalformedHeader, "")),
			}
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

	fn version(&self) -> u8 {
		self.version
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![self.version];
		vec.append(&mut self.pbe_header.encode_directly());
		vec.push(self.algorithm.clone() as u8);
		vec.append(&mut self.encrypted_encryption_key.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<EncryptionHeader> {
		let mut cursor = Cursor::new(data);
		let header_version = u8::decode_directly(&mut cursor)?;
		let pbe_header = PBEHeader::decode_directly(&mut cursor)?;
		let encryption_algorithm = match u8::decode_directly(&mut cursor)? {
			0 => EncryptionAlgorithm::AES128GCM,
			1 => EncryptionAlgorithm::AES256GCM,
			_ => return Err(ZffError::new_header_decode_error(ERROR_HEADER_DECODER_UNKNOWN_ENCRYPTION_ALGORITHM)),
		};
		let key_length = u64::decode_directly(&mut cursor)? as usize;
		let mut encryption_key = vec![0u8; key_length];
		cursor.read_exact(&mut encryption_key)?;
		Ok(EncryptionHeader::new(header_version, pbe_header, encryption_algorithm, encryption_key))
	}
}