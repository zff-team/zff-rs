// STD
use std::io::{Read,Cursor};
use std::fmt;

use crate::constants::DEFAULT_HEADER_VERSION_PBE_HEADER;
// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	KDFScheme,
	PBEScheme,
	ZffError,
	ZffErrorKind,
};

use crate::{
	HEADER_IDENTIFIER_PBE_HEADER,
	PBE_KDF_PARAMETERS_PBKDF2,
	PBE_KDF_PARAMETERS_SCRYPT,
	PBE_KDF_PARAMETERS_ARGON2ID,
	ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER_KDF,
	ERROR_HEADER_DECODER_UNKNOWN_PBE_SCHEME,
	ERROR_HEADER_DECODER_UNKNOWN_KDF_SCHEME,
	METADATA_EXT_TYPE_IDENTIFIER_UNKNOWN,
};

// - external
use byteorder::{BigEndian, ReadBytesExt};
#[cfg(feature = "serde")]
use serde::{
	Deserialize,
	Serialize,
};

/// The pbe header contains all informations for the encryption of the encryption key.\
/// The encryption key, used for the chunk encryption, can be found at the [EncryptionHeader](struct.EncryptionHeader.html) -
/// encrypted with an user password.\
/// This encryption of the encryption key is done via a password-based encryption (PBE).\
/// All metadata about this PBE can be found in this PBEHeader.\
#[derive(Debug,Clone,PartialEq,Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct PBEHeader {
	/// The kdf scheme used for the encryption key derivation.
	pub kdf_scheme: KDFScheme,
	/// The encryption scheme used for the encryption key derivation.
	pub encryption_scheme: PBEScheme,
	/// The kdf parameters.
	pub kdf_parameters: KDFParameters,
	/// The nonce used for the encryption of the encryption key.
	#[cfg_attr(feature = "serde", serde(serialize_with = "crate::helper::buffer_to_hex"))]
	pub pbencryption_nonce: [u8; 16],
}

impl PBEHeader {
	/// returns a new pbe header with the given values.
	pub fn new(
		kdf_scheme: KDFScheme,
		encryption_scheme: PBEScheme,
		kdf_parameters: KDFParameters,
		pbencryption_nonce: [u8; 16],
		) -> PBEHeader {
		Self {
			kdf_scheme,
			encryption_scheme,
			kdf_parameters,
			pbencryption_nonce,
		}
	}
}

impl HeaderCoding for PBEHeader {
	type Item = PBEHeader;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_PBE_HEADER
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_PBE_HEADER
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![Self::version(), self.kdf_scheme.clone() as u8, self.encryption_scheme.clone() as u8];
		vec.append(&mut self.kdf_parameters.encode_directly());
		vec.append(&mut self.pbencryption_nonce.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<PBEHeader> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?;
		let kdf_scheme = match u8::decode_directly(&mut cursor)? {
			0 => KDFScheme::PBKDF2SHA256,
			1 => KDFScheme::Scrypt,
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
		Ok(PBEHeader::new(kdf_scheme, encryption_scheme, kdf_params, encryption_nonce))
	}
}

// - implement fmt::Display
impl fmt::Display for PBEHeader {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl PBEHeader {
	fn struct_name(&self) -> &'static str {
		"PBEHeader"
	}
}

/// enum to handle the stored parameters for the appropriate key deriavation function (KDF).
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum KDFParameters {
	/// stores a struct [PBKDF2SHA256Parameters].
	PBKDF2SHA256Parameters(PBKDF2SHA256Parameters),
	/// stores a struct [ScryptParameters].
	ScryptParameters(ScryptParameters),
	/// stores a struct [Argon2idParameters].
	Argon2idParameters(Argon2idParameters),
}

impl ValueEncoder for KDFParameters {
	fn encode_directly(&self) -> Vec<u8> {
		match self {
			KDFParameters::PBKDF2SHA256Parameters(params) => params.encode_directly(),
			KDFParameters::ScryptParameters(params) => params.encode_directly(),
			KDFParameters::Argon2idParameters(params) => params.encode_directly(),
		}
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_UNKNOWN
	}
}

impl ValueDecoder for KDFParameters {
	type Item = KDFParameters;

	fn decode_directly<R: Read>(data: &mut R) -> Result<KDFParameters> {
		let identifier = data.read_u32::<BigEndian>()?;
		let size = u64::decode_directly(data)?;
		let mut params = vec![0u8; (size-12) as usize];
		data.read_exact(&mut params)?;
		
		let mut params_cursor = Cursor::new(params);

		if identifier == PBKDF2SHA256Parameters::identifier() {
			let iterations = u32::decode_directly(&mut params_cursor)?;
			let mut salt = [0; 32];
			params_cursor.read_exact(&mut salt)?;
			let parameters = PBKDF2SHA256Parameters::new(iterations, salt);
			Ok(KDFParameters::PBKDF2SHA256Parameters(parameters))
		} else if identifier == ScryptParameters::identifier() {
			let logn = u8::decode_directly(&mut params_cursor)?;
			let r = u32::decode_directly(&mut params_cursor)?;
			let p = u32::decode_directly(&mut params_cursor)?;
			let mut salt = [0; 32];
			params_cursor.read_exact(&mut salt)?;
			let parameters = ScryptParameters::new(logn, r, p, salt);
			Ok(KDFParameters::ScryptParameters(parameters))
		} else {
			Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER_KDF))
		}
	}
}

/// struct to store the parameters for the KDF PBKDF2-SHA256.
#[derive(Debug,Clone,Eq,PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct PBKDF2SHA256Parameters {
	/// The iterations to use.
	pub iterations: u32,
	/// The salt value.
	#[cfg_attr(feature = "serde", serde(serialize_with = "crate::helper::buffer_to_hex"))]
	pub salt: [u8; 32],
}

impl PBKDF2SHA256Parameters {
	/// returns a new [PBKDF2SHA256Parameters] with the given values.
	pub fn new(iterations: u32, salt: [u8; 32]) -> PBKDF2SHA256Parameters {
		Self {
			iterations,
			salt,
		}
	}
}

impl HeaderCoding for PBKDF2SHA256Parameters {
	type Item = PBKDF2SHA256Parameters;

	fn identifier() -> u32 {
		PBE_KDF_PARAMETERS_PBKDF2
	}

	/// just a placeholder, because this structure is not a header, but only a part of another header.
	fn version() -> u8 {
		0
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.iterations.encode_directly());
		vec.append(&mut self.salt.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<PBKDF2SHA256Parameters> {
		let mut cursor = Cursor::new(data);

		let iterations = u32::decode_directly(&mut cursor)?;
		let mut salt = [0; 32];
		cursor.read_exact(&mut salt)?;
		let parameters = PBKDF2SHA256Parameters::new(iterations, salt);
		Ok(parameters)
	}

}

/// struct to store the parameters for the KDF Scrypt.
#[derive(Debug,Clone,Eq,PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ScryptParameters {
	/// The log n parameter for Scrypt.
	pub logn: u8,
	/// The r parameter for Scrypt.
	pub r: u32,
	/// The p parameter for Scrypt.
	pub p: u32,
	/// The used salt.
	#[cfg_attr(feature = "serde", serde(serialize_with = "crate::helper::buffer_to_hex"))]
	pub salt: [u8; 32],
}

impl ScryptParameters {
	/// returns a new [ScryptParameters] with the given values.
	pub fn new(logn: u8, r: u32, p: u32, salt: [u8; 32]) -> ScryptParameters {
		Self {
			logn,
			r,
			p,
			salt,
		}
	}
}

impl HeaderCoding for ScryptParameters {
	type Item = ScryptParameters;

	fn identifier() -> u32 {
		PBE_KDF_PARAMETERS_SCRYPT
	}

	/// just a placeholder, because this structure is not a header, but only a part of another header.
	fn version() -> u8 {
		0
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.logn.encode_directly());
		vec.append(&mut self.r.encode_directly());
		vec.append(&mut self.p.encode_directly());
		vec.append(&mut self.salt.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<ScryptParameters> {
		let mut cursor = Cursor::new(data);

		let logn = u8::decode_directly(&mut cursor)?;
		let r = u32::decode_directly(&mut cursor)?;
		let p = u32::decode_directly(&mut cursor)?;
		let mut salt = [0; 32];
		cursor.read_exact(&mut salt)?;
		let parameters = ScryptParameters::new(logn, r, p, salt);
		Ok(parameters)
	}

}


/// struct to store the parameters for the KDF Scrypt.
#[derive(Debug,Clone,Eq,PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Argon2idParameters {
	/// The memory cost parameter for Argon2id.
	pub mem_cost: u32,
	/// The used number of lanes for Argon2id.
	pub lanes: u32,
	/// The iterations value for Argon2id.
	pub iterations: u32,
	/// The used salt.
	pub salt: [u8; 32],
}

impl Argon2idParameters {
	/// returns a new [ScryptParameters] with the given values.
	pub fn new(mem_cost: u32, lanes: u32, iterations: u32, salt: [u8; 32]) -> Argon2idParameters {
		Self {
			mem_cost,
			lanes,
			iterations,
			salt,
		}
	}
}

impl HeaderCoding for Argon2idParameters {
	type Item = Argon2idParameters;

	fn identifier() -> u32 {
		PBE_KDF_PARAMETERS_ARGON2ID
	}

	/// just a placeholder, because this structure is not a header, but only a part of another header.
	fn version() -> u8 {
		0
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.mem_cost.encode_directly());
		vec.append(&mut self.lanes.encode_directly());
		vec.append(&mut self.iterations.encode_directly());
		vec.append(&mut self.salt.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<Argon2idParameters> {
		let mut cursor = Cursor::new(data);
		let mem_cost = u32::decode_directly(&mut cursor)?;
		let lanes = u32::decode_directly(&mut cursor)?;
		let iterations = u32::decode_directly(&mut cursor)?;
		let mut salt = [0; 32];
		cursor.read_exact(&mut salt)?;
		let parameters = Argon2idParameters::new(mem_cost, lanes, iterations, salt);
		Ok(parameters)
	}

}