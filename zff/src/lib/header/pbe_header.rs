// STD
use std::io::{Read,Cursor};

// - internal
use crate::{
	Result,
	HeaderObject,
	HeaderEncoder,
	HeaderDecoder,
	ValueEncoder,
	ValueDecoder,
	KDFScheme,
	PBEScheme,
	ZffError,
	ZffErrorKind,
};

use crate::{
	HEADER_IDENTIFIER_PBE_HEADER,
	PBE_KDF_PARAMETERS,
	ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER_KDF,
	ERROR_HEADER_DECODER_UNKNOWN_PBE_SCHEME,
	ERROR_HEADER_DECODER_UNKNOWN_KDF_SCHEME,
};

// - external
use serde::Serialize;
use serde::ser::{Serialize as SerializeTrait, Serializer, SerializeStruct};
use hex::ToHex;

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

	/// returns the kdf scheme.
	pub fn kdf_scheme(&self) -> &KDFScheme {
		&self.kdf_scheme
	}

	/// returns the encryption scheme.
	pub fn encryption_scheme(&self) -> &PBEScheme {
		&self.encryption_scheme
	}

	/// returns the kdf parameters.
	pub fn kdf_parameters(&self) -> &KDFParameters {
		&self.kdf_parameters
	}

	/// returns the pbe nonce.
	pub fn nonce(&self) -> &[u8; 16] {
		&self.pbencryption_nonce
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

impl HeaderEncoder for PBEHeader {}

impl HeaderDecoder for PBEHeader {
	type Item = PBEHeader;

	fn decode_content(data: Vec<u8>) -> Result<PBEHeader> {
		let mut cursor = Cursor::new(data);

		let header_version = u8::decode_directly(&mut cursor)?;
		let kdf_scheme = match u8::decode_directly(&mut cursor)? {
			0 => KDFScheme::PBKDF2SHA256,
			_ => return Err(ZffError::new_header_decode_error(ERROR_HEADER_DECODER_UNKNOWN_KDF_SCHEME))
		};
		let encryption_scheme = match u8::decode_directly(&mut cursor)? {
			0 => PBEScheme::AES128CBC,
			1 => PBEScheme::AES256CBC,
			_ => return Err(ZffError::new_header_decode_error(ERROR_HEADER_DECODER_UNKNOWN_PBE_SCHEME)),
		};
		let kdf_params = KDFParameters::decode_directly(&mut cursor)?;
		let mut encryption_nonce = [0; 16];
		cursor.read_exact(&mut encryption_nonce)?;
		Ok(PBEHeader::new(header_version, kdf_scheme, encryption_scheme, kdf_params, encryption_nonce))
	}
}

impl SerializeTrait for PBEHeader {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PBEHeader", 10)?;
        state.serialize_field("header_version", &self.header_version)?;
        state.serialize_field("kdf_scheme", &self.kdf_scheme)?;
        state.serialize_field("encryption_scheme", &self.encryption_scheme)?;
        match &self.kdf_parameters {
        	KDFParameters::PBKDF2SHA256Parameters(params) => state.serialize_field("pbkdf2sha256_parameters", &params)?,
        }
        state.serialize_field("pbencryption_nonce", &self.pbencryption_nonce.encode_hex::<String>())?;
        state.end()
    }
}

/// enum to handle the stored parameters for the appropriate key deriavation function (KDF).
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Serialize)]
pub enum KDFParameters {
	/// stores a struct [PBKDF2SHA256Parameters].
	PBKDF2SHA256Parameters(PBKDF2SHA256Parameters),
}

impl ValueEncoder for KDFParameters {
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

impl ValueDecoder for KDFParameters {
	type Item = KDFParameters;

	fn decode_directly<R: Read>(data: &mut R) -> Result<KDFParameters> {
		if let Ok(params) = PBKDF2SHA256Parameters::decode_directly(data) {
			return Ok(KDFParameters::PBKDF2SHA256Parameters(params));
		};
		return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER_KDF));
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

	/// returns the number of iterations
	pub fn iterations(&self) -> u16 {
		self.iterations
	}

	/// returns the salt
	pub fn salt(&self) -> &[u8; 32] {
		&self.salt
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

impl HeaderEncoder for PBKDF2SHA256Parameters {}

impl HeaderDecoder for PBKDF2SHA256Parameters {
	type Item = PBKDF2SHA256Parameters;

	fn decode_content(data: Vec<u8>) -> Result<PBKDF2SHA256Parameters> {
		let mut cursor = Cursor::new(data);

		let iterations = u16::decode_directly(&mut cursor)?;
		let mut salt = [0; 32];
		cursor.read_exact(&mut salt)?;
		let parameters = PBKDF2SHA256Parameters::new(iterations, salt);
		Ok(parameters)
	}

}

impl SerializeTrait for PBKDF2SHA256Parameters {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("PBKDF2SHA256Parameters", 10)?;
        state.serialize_field("iterations", &self.iterations)?;
        state.serialize_field("salt", &self.salt.encode_hex::<String>())?;
        state.end()
    }
}