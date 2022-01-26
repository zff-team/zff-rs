// - STD
use std::io::{Cursor, Read};
use std::fmt;

// - external
use serde::{Serialize};

// - internal
use crate::{
	Result,
	HeaderCoding,
	Encryption,
	ValueEncoder,
	ValueDecoder,
	ZffError,
	ZffErrorKind,
};

use crate::{
	ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER,
	DEFAULT_LENGTH_VALUE_HEADER_LENGTH,
	DEFAULT_LENGTH_HEADER_IDENTIFIER,
	HEADER_IDENTIFIER_OBJECT_HEADER,
	SignatureFlag,
};

use crate::version2::header::{
	EncryptionHeader,
	CompressionHeader,
	DescriptionHeader,
};

#[derive(Debug,Clone)]
pub struct ObjectHeader {
	version: u8,
	object_number: u64,
	encryption_header: Option<EncryptionHeader>,
	compression_header: CompressionHeader,
	signature_flag: SignatureFlag,
	description_header: DescriptionHeader,
	object_type: ObjectType
}

impl ObjectHeader {
	pub fn new(version: u8,
		object_number: u64,
		encryption_header: Option<EncryptionHeader>,
		compression_header: CompressionHeader,
		signature_flag: SignatureFlag,
		description_header: DescriptionHeader,
		object_type: ObjectType) -> ObjectHeader {
		Self {
			version: version,
			object_number: object_number,
			encryption_header: encryption_header,
			compression_header: compression_header,
			signature_flag: signature_flag,
			description_header: description_header,
			object_type: object_type,
		}
	}
	
	pub fn object_number(&self) -> u64 {
		self.object_number
	}
	
	pub fn description_header(&self) -> DescriptionHeader {
		self.description_header.clone()
	}
	
	pub fn object_type(&self) -> ObjectType {
		self.object_type.clone()
	}

	pub fn encryption_header(&self) -> Option<EncryptionHeader> {
		self.encryption_header.clone()
	}

	pub fn compression_header(&self) -> CompressionHeader {
		self.compression_header.clone()
	}

	/// returns, if the chunks has a ed25519 signature or not.
	pub fn has_per_chunk_signature(&self) -> bool {
		match &self.signature_flag {
			SignatureFlag::PerChunkSignatures => return true,
			_ => return false,
		}
	}

	pub fn has_hash_signatures(&self) -> bool {
		match &self.signature_flag {
			SignatureFlag::NoSignatures => return false,
			_ => return true,
		}
	}


	/// encodes the object header to a ```Vec<u8>```. The encryption flag will be set to 2.
	/// # Error
	/// The method returns an error, if the encryption header is missing (=None).
	/// The method returns an error, if the encryption fails.
	pub fn encode_encrypted_header_directly<K>(&self, key: K) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
	{
		let mut vec = Vec::new();
		let mut encoded_header = self.encode_encrypted_header(key)?;
		let identifier = HEADER_IDENTIFIER_OBJECT_HEADER;
		let encoded_header_length = 4 + 8 + (encoded_header.len() as u64); //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.append(&mut encoded_header);

		Ok(vec)
	}

	fn encode_encrypted_header<K>(&self, key: K) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>
	{
		let encryption_header = match &self.encryption_header {
			None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionHeader, "")),
			Some(header) => {
				header
			}
		};
		let encryption_flag: u8 = 2;

		let mut vec = Vec::new();
		vec.push(self.version);
		vec.append(&mut self.object_number.encode_directly());
		vec.push(encryption_flag);
		vec.append(&mut encryption_header.encode_directly());

		let mut data_to_encrypt = Vec::new();
		data_to_encrypt.append(&mut self.encode_content());

		let encrypted_data = Encryption::encrypt_header(
			key, data_to_encrypt,
			encryption_header.nonce(),
			encryption_header.algorithm()
			)?;
		vec.append(&mut encrypted_data.encode_directly());
		return Ok(vec);
	}

	fn encode_content(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		
		vec.append(&mut self.compression_header.encode_directly());
		vec.push(self.signature_flag.clone() as u8);
		vec.append(&mut self.description_header.encode_directly());
		vec
	}

	/// decodes the encrypted header with the given password.
	pub fn decode_encrypted_header_with_password<R, P>(data: &mut R, password: P) -> Result<ObjectHeader>
	where
		R: Read,
		P: AsRef<[u8]>,
	{
		if !Self::check_identifier(data) {
			return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER));
		};
		let header_length = Self::decode_header_length(data)? as usize;
		let mut header_content = vec![0u8; header_length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
		data.read_exact(&mut header_content)?;
		let mut cursor = Cursor::new(header_content);
		let header_version = u8::decode_directly(&mut cursor)?;
		let object_number = u64::decode_directly(&mut cursor)?;
		let encryption_flag = u8::decode_directly(&mut cursor)?;
		if encryption_flag != 2 {
			return Err(ZffError::new(ZffErrorKind::HeaderDecodeEncryptedHeader, "")); //TODO
		}
		let encryption_header = EncryptionHeader::decode_directly(&mut cursor)?;
		let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
		let encryption_key = encryption_header.decrypt_encryption_key(password)?;
		let nonce = encryption_header.nonce();
		let algorithm = encryption_header.algorithm();
		let decrypted_data = Encryption::decrypt_header(encryption_key, encrypted_data, nonce, algorithm)?;
		let mut cursor = Cursor::new(decrypted_data);
		let (compression_header,
			signature_flag,
			description_header,
			object_type) = Self::decode_inner_content(&mut cursor)?;
		let object_header = Self::new(
			header_version,
			object_number,
			Some(encryption_header),
			compression_header,
			signature_flag,
			description_header,
			object_type);
		Ok(object_header)
	}

	fn decode_inner_content<R: Read>(inner_content: &mut R) -> Result<(
		CompressionHeader,
		SignatureFlag,
		DescriptionHeader,
		ObjectType,
		)> {
		let compression_header = CompressionHeader::decode_directly(inner_content)?;
		let signature_flag = match u8::decode_directly(inner_content)? {
			0 => SignatureFlag::NoSignatures,
			1 => SignatureFlag::HashValueSignatureOnly,
			2 => SignatureFlag::PerChunkSignatures,
			value @ _ => return Err(ZffError::new(ZffErrorKind::InvalidFlagValue, format!("signature_flag value: {value}"))), //TODO: move to constants...
		};
		let description_header = DescriptionHeader::decode_directly(inner_content)?;
		let object_type = match u8::decode_directly(inner_content)? {
			0 => ObjectType::Physical,
			1 => ObjectType::Logical,
			value @ _ => return Err(ZffError::new(ZffErrorKind::InvalidFlagValue, format!("object_type value: {value}"))), //TODO: move to constants...
		};
		let inner_content = (
			compression_header,
			signature_flag,
			description_header,
			object_type);
		Ok(inner_content)
	}
}

/// Defines all hashing algorithms, which are implemented in zff.
#[repr(u8)]
#[derive(Debug,Clone,Eq,PartialEq,Hash,Serialize)]
pub enum ObjectType {
	Physical = 1,
	Logical = 2,
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let msg = match self {
			ObjectType::Physical => "Physical",
			ObjectType::Logical => "Logical",
		};
		write!(f, "{}", msg)
	}
}

impl HeaderCoding for ObjectHeader {
	type Item = ObjectHeader;
	fn identifier() -> u32 {
		HEADER_IDENTIFIER_OBJECT_HEADER
	}

	fn version(&self) -> u8 {
		self.version
	}

	/// encodes the (header) value/object directly (= without key).
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_header = self.encode_header();
		let identifier = Self::identifier();
		let encoded_header_length = (DEFAULT_LENGTH_HEADER_IDENTIFIER + DEFAULT_LENGTH_VALUE_HEADER_LENGTH + encoded_header.len()) as u64; //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.push(self.version);
		vec.append(&mut self.object_number.encode_directly());
		vec.append(&mut encoded_header);

		vec
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		match &self.encryption_header {
			None => {
				let encryption_flag: u8 = 0;
				vec.push(encryption_flag);
			},
			Some(header) => {
				let encryption_flag: u8 = 1;
				vec.push(encryption_flag);
				vec.append(&mut header.encode_directly());
			},
		};

		vec.append(&mut self.encode_content());

		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<ObjectHeader> {
		let mut cursor = Cursor::new(data);
		let version = u8::decode_directly(&mut cursor)?;
		let object_number = u64::decode_directly(&mut cursor)?;
		//encryption flag:
		let mut encryption_header = None;
		let encryption_flag = u8::decode_directly(&mut cursor)?;
		if encryption_flag == 1 {
			encryption_header = Some(EncryptionHeader::decode_directly(&mut cursor)?);
		} else if encryption_flag > 1 {
			return Err(ZffError::new(ZffErrorKind::HeaderDecodeEncryptedHeader, ""))//TODO
		}
		let (compression_header,
			signature_flag,
			description_header,
			object_type) = Self::decode_inner_content(&mut cursor)?;
		let object_header = Self::new(
			version,
			object_number,
			encryption_header,
			compression_header,
			signature_flag,
			description_header,
			object_type);
		Ok(object_header)
	}
}