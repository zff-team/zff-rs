// - STD
use std::borrow::Borrow;
use std::cmp::{PartialEq};
use std::io::{Cursor, Read};
use std::fmt;
use std::collections::{BTreeMap};

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	ZffError,
	ZffErrorKind,
	header::{EncryptionInformation},
	Encryption,
	HEADER_IDENTIFIER_VIRTUAL_MAPPING_INFORMATION,
	HEADER_IDENTIFIER_VIRTUAL_LAYER,
	DEFAULT_HEADER_VERSION_VIRTUAL_MAPPING_INFORMATION,
	DEFAULT_HEADER_VERSION_VIRTUAL_LAYER,
	DEFAULT_LENGTH_HEADER_IDENTIFIER,
	DEFAULT_LENGTH_VALUE_HEADER_LENGTH,
	ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER,
};

// - external
#[cfg(feature = "serde")]
use serde::{
	Deserialize,
	Serialize,
	ser::{Serializer, SerializeStruct},
};
#[cfg(feature = "serde")]
use hex;

#[derive(Debug,Clone,PartialEq,Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct VirtualMappingInformation {
	pub object_number: u64,
	pub start_chunk_no: u64,
	pub chunk_offset: u64,
	pub length: u64,	
}

impl VirtualMappingInformation {
	/// returns a new [VirtualMappingInformation] with the given values.
	pub fn with_data(object_number: u64, start_chunk_no: u64, chunk_offset: u64, length: u64) -> Self {
		Self {
			object_number,
			start_chunk_no,
			chunk_offset,
			length,
		}
	}

	/// encrypts the mapping information by the given encryption information and the original offset as nonce value,
	/// and returns the encrypted data.
	pub fn encrypt_directly<E>(&self, encryption_information: E, offset: u64) -> Result<Vec<u8>>
	where
		E: Borrow<EncryptionInformation>
	{
		let mut vec = Vec::new();
		let encrypted_content = Encryption::encrypt_virtual_mapping_information(
			&encryption_information.borrow().encryption_key, 
			self.encode_content(), 
			offset, 
			&encryption_information.borrow().algorithm)?;
		let identifier = Self::identifier();
		let encoded_header_length = (
			DEFAULT_LENGTH_HEADER_IDENTIFIER +
			DEFAULT_LENGTH_VALUE_HEADER_LENGTH + 
			self.version().encode_directly().len() +
			encrypted_content.encode_directly().len()) as u64; //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.encode_directly());
		vec.append(&mut self.version().encode_directly());
		vec.append(&mut encrypted_content.encode_directly());

		Ok(vec)
	}

	/// decodes the encrypted structure with the given [crate::header::EncryptionInformation] and the appropriate original data offset.
	pub fn decode_encrypted_structure_with_key<R, E>(data: &mut R, offset: u64, encryption_information: E) -> Result<Self>
	where
		R: Read,
		E: Borrow<EncryptionInformation>
	{
		if !Self::check_identifier(data) {
			return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER));
		};
		let header_length = Self::decode_header_length(data)? as usize;
		let mut header_content = vec![0u8; header_length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
		data.read_exact(&mut header_content)?;
		let mut cursor = Cursor::new(header_content);
		let version = u8::decode_directly(&mut cursor)?;
		if version != DEFAULT_HEADER_VERSION_VIRTUAL_MAPPING_INFORMATION {
			return Err(ZffError::new(ZffErrorKind::UnsupportedVersion, version.to_string()))
		};

		let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
		let algorithm = &encryption_information.borrow().algorithm;
		let decrypted_data = Encryption::decrypt_virtual_mapping_information(
			&encryption_information.borrow().encryption_key, 
			encrypted_data, 
			offset, 
			algorithm)?;
		let mut cursor = Cursor::new(decrypted_data);
		let (object_number,
			start_chunk_no,
			chunk_offset,
			length) = Self::decode_inner_content(&mut cursor)?;
		Ok(Self::with_data(
			object_number,
			start_chunk_no,
			chunk_offset,
			length))
	}

	fn encode_content(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.object_number.encode_directly());
		vec.append(&mut self.start_chunk_no.encode_directly());
		vec.append(&mut self.chunk_offset.encode_directly());
		vec.append(&mut self.length.encode_directly());
		vec
	}

	fn decode_inner_content<R: Read>(data: &mut R) -> Result<(
		u64, //object_number
		u64, //start_chunk_no
		u64, //chunk_offset
		u64, //length
		)> {
		let object_number = u64::decode_directly(data)?;
		let start_chunk_no = u64::decode_directly(data)?;
		let chunk_offset = u64::decode_directly(data)?;
		let length = u64::decode_directly(data)?;
		Ok((
			object_number,
			start_chunk_no,
			chunk_offset,
			length
			))
	}

}

impl HeaderCoding for VirtualMappingInformation {
	type Item = VirtualMappingInformation;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_VIRTUAL_MAPPING_INFORMATION
	}

	fn version(&self) -> u8 {
		DEFAULT_HEADER_VERSION_VIRTUAL_MAPPING_INFORMATION
	}
	
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![self.version()];
		vec.append(&mut self.encode_content());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		let version = u8::decode_directly(&mut cursor)?;
		if version != DEFAULT_HEADER_VERSION_VIRTUAL_MAPPING_INFORMATION {
			return Err(ZffError::new(ZffErrorKind::UnsupportedVersion, version.to_string()))
		};
		let (object_number, 
			start_chunk_no, 
			chunk_offset,
			length) = Self::decode_inner_content(&mut cursor)?;

		Ok(Self::with_data(object_number, start_chunk_no, chunk_offset, length))
	}
}

// - implement fmt::Display
impl fmt::Display for VirtualMappingInformation {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl VirtualMappingInformation {
	fn struct_name(&self) -> &'static str {
		"VirtualMappingInformation"
	}
}


#[derive(Debug,Clone,PartialEq,Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct VirtualLayer {
	pub depth: u8,
	pub offsetmap: BTreeMap<u64, u64>,
}

impl VirtualLayer {
	/// returns a new [VirtualLayer] with the given values.
	pub fn with_data(depth: u8, offsetmap: BTreeMap<u64, u64>) -> Self {
		Self {
			depth,
			offsetmap,
		}
	}

	/// encrypts the mapping information by the given encryption information and the original offset as nonce value,
	/// and returns the encrypted data.
	pub fn encrypt_directly<E>(&self, encryption_information: E) -> Result<Vec<u8>>
	where
		E: Borrow<EncryptionInformation>
	{
		let mut vec = Vec::new();
		let encrypted_content = Encryption::encrypt_virtual_layer(
			&encryption_information.borrow().encryption_key, 
			self.encode_content(), 
			self.depth.into(), 
			&encryption_information.borrow().algorithm)?;
		let identifier = Self::identifier();
		let encoded_header_length = (
			DEFAULT_LENGTH_HEADER_IDENTIFIER +
			DEFAULT_LENGTH_VALUE_HEADER_LENGTH + 
			self.version().encode_directly().len() +
			self.depth.encode_directly().len() +
			encrypted_content.encode_directly().len()) as u64; //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.encode_directly());
		vec.append(&mut self.version().encode_directly());
		vec.append(&mut self.depth.encode_directly());
		vec.append(&mut encrypted_content.encode_directly());

		Ok(vec)
	}

	/// decodes the encrypted structure with the given [crate::header::EncryptionInformation] and the appropriate original data offset.
	pub fn decode_encrypted_structure_with_key<R, E>(data: &mut R, encryption_information: E) -> Result<Self>
	where
		R: Read,
		E: Borrow<EncryptionInformation>
	{
		if !Self::check_identifier(data) {
			return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER));
		};
		let header_length = Self::decode_header_length(data)? as usize;
		let mut header_content = vec![0u8; header_length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
		data.read_exact(&mut header_content)?;
		let mut cursor = Cursor::new(header_content);
		let version = u8::decode_directly(&mut cursor)?;
		if version != DEFAULT_HEADER_VERSION_VIRTUAL_LAYER {
			return Err(ZffError::new(ZffErrorKind::UnsupportedVersion, version.to_string()))
		};
		let depth = u8::decode_directly(&mut cursor)?;
		let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
		let algorithm = &encryption_information.borrow().algorithm;
		let decrypted_data = Encryption::decrypt_virtual_mapping_information(
			&encryption_information.borrow().encryption_key, 
			encrypted_data, 
			depth.into(), 
			algorithm)?;
		let mut cursor = Cursor::new(decrypted_data);
		let offsetmap = Self::decode_inner_content(&mut cursor)?;
		Ok(Self::with_data(
			depth,
			offsetmap
			))
	}

	fn encode_content(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.offsetmap.encode_directly());
		vec
	}

	fn decode_inner_content<R: Read>(data: &mut R) -> Result<BTreeMap<u64, u64>> {
		let offsetmap = BTreeMap::<u64, u64>::decode_directly(data)?;
		Ok(offsetmap)
	}
}

impl HeaderCoding for VirtualLayer {
	type Item = VirtualLayer;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_VIRTUAL_LAYER
	}

	fn version(&self) -> u8 {
		DEFAULT_HEADER_VERSION_VIRTUAL_LAYER
	}
	
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![self.version()];
		vec.append(&mut self.depth.encode_directly());
		vec.append(&mut self.encode_content());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		let version = u8::decode_directly(&mut cursor)?;
		if version != DEFAULT_HEADER_VERSION_VIRTUAL_LAYER {
			return Err(ZffError::new(ZffErrorKind::UnsupportedVersion, version.to_string()))
		};
		let depth = u8::decode_directly(&mut cursor)?;
		let offsetmap = Self::decode_inner_content(&mut cursor)?;

		Ok(Self::with_data(depth, offsetmap))
	}
}

// - implement fmt::Display
impl fmt::Display for VirtualLayer {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl VirtualLayer {
	fn struct_name(&self) -> &'static str {
		"VirtualLayer"
	}
}