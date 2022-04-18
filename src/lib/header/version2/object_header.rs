// - STD
use std::io::{Cursor, Read};
use std::fmt;
use std::cmp::{PartialEq,Eq};
use std::hash::{Hash, Hasher};

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

use crate::header::{
	EncryptionHeader,
	CompressionHeader,
	DescriptionHeader,
};

/// Each object starts with a [ObjectHeader]. The [ObjectHeader] contains several metadata of the appropriate underlying object.
/// The following metadata are stored in an [ObjectHeader]:
/// - The appropriate number of the objects (the first object always starts with 1)
/// - An [crate::header::EncryptionHeader], if an encryption was used.
/// - A [crate::header::CompressionHeader], containing the appropriate compression information
/// - A flag, if a signature method was used.
/// - A [crate::header::DescriptionHeader] for this object.
/// - The [ObjectType] of this object. 
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
	/// creates a new object with the given values
	pub fn new(version: u8,
		object_number: u64,
		encryption_header: Option<EncryptionHeader>,
		compression_header: CompressionHeader,
		signature_flag: SignatureFlag,
		description_header: DescriptionHeader,
		object_type: ObjectType) -> ObjectHeader {
		Self {
			version,
			object_number,
			encryption_header,
			compression_header,
			signature_flag,
			description_header,
			object_type,
		}
	}

	/// sets the object number
	pub fn set_object_number(&mut self, object_number: u64) {
		self.object_number = object_number
	}
	
	/// returns the object number
	pub fn object_number(&self) -> u64 {
		self.object_number
	}
	
	/// returns the [crate::header::DescriptionHeader]
	pub fn description_header(&self) -> DescriptionHeader {
		self.description_header.clone()
	}
	
	/// returns the [ObjectType]
	pub fn object_type(&self) -> ObjectType {
		self.object_type.clone()
	}

	/// returns a reference to the underlying [crate::header::EncryptionHeader], if available.
	pub fn encryption_header(&self) -> Option<&EncryptionHeader> {
		self.encryption_header.as_ref()
	}

	/// returns the underlying [crate::header::CompressionHeader]
	pub fn compression_header(&self) -> CompressionHeader {
		self.compression_header.clone()
	}

	/// returns, if the chunks has a ed25519 signature or not.
	pub fn has_per_chunk_signature(&self) -> bool {
		matches!(&self.signature_flag, SignatureFlag::PerChunkSignatures)
	}

	/// checks if a signature method was used. Returns true if and false if not.
	pub fn has_hash_signatures(&self) -> bool {
		!matches!(&self.signature_flag, SignatureFlag::NoSignatures)
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
		vec.append(&mut self.version.encode_directly());
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
		Ok(vec)
	}

	fn encode_content(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		
		vec.append(&mut self.compression_header.encode_directly());
		vec.push(self.signature_flag.clone() as u8);
		vec.append(&mut self.description_header.encode_directly());
		vec.push(self.object_type.clone() as u8);
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
			value => return Err(ZffError::new(ZffErrorKind::InvalidFlagValue, format!("signature_flag value: {value}"))), //TODO: move to constants...
		};
		let description_header = DescriptionHeader::decode_directly(inner_content)?;
		let object_type = match u8::decode_directly(inner_content)? {
			1 => ObjectType::Physical,
			2 => ObjectType::Logical,
			value => return Err(ZffError::new(ZffErrorKind::InvalidFlagValue, format!("object_type value: {value}"))), //TODO: move to constants...
		};
		let inner_content = (
			compression_header,
			signature_flag,
			description_header,
			object_type);
		Ok(inner_content)
	}
}

/// Defines the [ObjectType], which can be used in zff container.
#[repr(u8)]
#[derive(Debug,Clone,Eq,PartialEq,Hash)]
pub enum ObjectType {
	/// An object containing a physical dump.
	Physical = 0,
	/// An object, containing logical files.
	Logical = 1,
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
		let mut encoded_object_number = self.object_number.encode_directly();
		let mut encoded_header = self.encode_header();
		let identifier = Self::identifier();
		let encoded_header_length = (DEFAULT_LENGTH_HEADER_IDENTIFIER + DEFAULT_LENGTH_VALUE_HEADER_LENGTH + encoded_header.len() + encoded_object_number.len() + 1) as u64; //4 bytes identifier + 8 bytes for length + length of encoded content + len of object number + length of version
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.push(self.version);
		vec.append(&mut encoded_object_number);
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
		let encryption_flag = u8::decode_directly(&mut cursor)?;
		let encryption_header = match encryption_flag {
			0 => None,
			1 => Some(EncryptionHeader::decode_directly(&mut cursor)?),
			_ => return Err(ZffError::new(ZffErrorKind::HeaderDecodeEncryptedHeader, "")) //TODO
		};
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

impl PartialEq for ObjectHeader {
    fn eq(&self, other: &Self) -> bool {
        self.object_number == other.object_number
    }
}

impl Eq for ObjectHeader {}

impl Hash for ObjectHeader {
	fn hash<H: Hasher>(&self, state: &mut H) {
        self.object_number.hash(state);
    }
}