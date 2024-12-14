// - STD
use std::borrow::Borrow;
use std::cmp::PartialEq;
use std::io::{Cursor, Read};
use std::fmt;
use std::collections::{BTreeMap, BTreeSet};

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	ZffError,
	ZffErrorKind,
	header::EncryptionInformation,
	Encryption,
	HEADER_IDENTIFIER_VIRTUAL_MAPPING_INFORMATION,
	HEADER_IDENTIFIER_VIRTUAL_OBJECT_MAP,
	DEFAULT_HEADER_VERSION_VIRTUAL_MAPPING_INFORMATION,
	DEFAULT_HEADER_VERSION_VIRTUAL_OBJECT_MAP,
	DEFAULT_LENGTH_HEADER_IDENTIFIER,
	DEFAULT_LENGTH_VALUE_HEADER_LENGTH,
	ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER,
};

// - external
#[cfg(feature = "serde")]
use serde::{
	Deserialize,
	Serialize,
};


/// Contains the information of the appropriate virtual mapping.
/// The counterpart offset has to be stored outside of this structure (in the [VirtualObjectMap]).
#[derive(Debug,Clone,PartialEq,Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct VirtualMappingInformation {
	/// The object number of the appropriate start chunk.
	/// This is necessary to be able to decrypt an encrypted chunk.
	pub object_number: u64,
	/// The number of the first affected chunk for this offset.
	pub start_chunk_no: u64,
	/// The start offset inside of this chunk.
	pub chunk_offset: u64,
	/// The full length of the data offset.
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
		let encrypted_content = VirtualMappingInformation::encrypt(
			&encryption_information.borrow().encryption_key, 
			self.encode_content(), 
			offset, 
			&encryption_information.borrow().algorithm)?;
		let identifier = Self::identifier();
		let encoded_header_length = (
			DEFAULT_LENGTH_HEADER_IDENTIFIER +
			DEFAULT_LENGTH_VALUE_HEADER_LENGTH + 
			Self::version().encode_directly().len() +
			encrypted_content.encode_directly().len()) as u64; //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.encode_directly());
		vec.append(&mut Self::version().encode_directly());
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
		Self::check_version(&mut cursor)?; // check version (and skip it)
		let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
		let algorithm = &encryption_information.borrow().algorithm;
		let decrypted_data = VirtualMappingInformation::decrypt(
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

impl Encryption for VirtualMappingInformation {
	fn crypto_nonce_padding() -> u8 {
		0b00000010
	}
}

impl HeaderCoding for VirtualMappingInformation {
	type Item = VirtualMappingInformation;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_VIRTUAL_MAPPING_INFORMATION
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_VIRTUAL_MAPPING_INFORMATION
	}
	
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![Self::version()];
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

/// The [VirtualObjectMap] contains the appropriate offset map to find the counterpart [VirtualMappingInformation].
/// 
/// As the name of this struct already suggests, this structure can be layered multiple times.
#[derive(Debug,Clone,PartialEq,Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct VirtualObjectMap {
	/// The appropriate offset maps.
	pub offsetmaps: BTreeSet<BTreeMap<u64, (u64, u64)>>, // <original offset, (segment number, offset for the appropriate VMI)>
}

impl VirtualObjectMap {
	/// returns a new [VirtualObjectMap] with the given values.
	pub fn with_data(offsetmaps: BTreeSet<BTreeMap<u64, (u64, u64)>>) -> Self {
		Self {
			offsetmaps,
		}
	}

	/// encrypts the mapping information by the given encryption information and the original offset as nonce value,
	/// and returns the encrypted data.
	/// Needs the object number of the appropriate virtual Object to encrypt.
	pub fn encrypt_directly<E>(&self, encryption_information: E, object_number: u64) -> Result<Vec<u8>>
	where
		E: Borrow<EncryptionInformation>
	{
		let mut vec = Vec::new();
		let encrypted_content = VirtualObjectMap::encrypt(
			&encryption_information.borrow().encryption_key, 
			self.encode_content(), 
			object_number, 
			&encryption_information.borrow().algorithm)?;
		let identifier = Self::identifier();
		let encoded_header_length = (
			DEFAULT_LENGTH_HEADER_IDENTIFIER +
			DEFAULT_LENGTH_VALUE_HEADER_LENGTH + 
			Self::version().encode_directly().len() +
			encrypted_content.encode_directly().len()) as u64; //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.encode_directly());
		vec.append(&mut Self::version().encode_directly());
		vec.append(&mut encrypted_content.encode_directly());

		Ok(vec)
	}

	/// decodes the encrypted structure with the given [crate::header::EncryptionInformation] and the appropriate original data offset.
	pub fn decode_encrypted_structure_with_key<R, E>(data: &mut R, encryption_information: E, object_number: u64) -> Result<Self>
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
		if version != DEFAULT_HEADER_VERSION_VIRTUAL_OBJECT_MAP {
			return Err(ZffError::new(ZffErrorKind::UnsupportedVersion, version.to_string()))
		};
		let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
		let algorithm = &encryption_information.borrow().algorithm;
		let decrypted_data = VirtualMappingInformation::decrypt(
			&encryption_information.borrow().encryption_key, 
			encrypted_data,
			object_number, 
			algorithm)?;
		let mut cursor = Cursor::new(decrypted_data);
		let offsetmaps = Self::decode_inner_content(&mut cursor)?;
		Ok(Self::with_data(offsetmaps))
	}

	fn encode_content(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.offsetmaps.encode_directly());
		vec
	}

	fn decode_inner_content<R: Read>(data: &mut R) -> Result<BTreeSet<BTreeMap<u64, (u64, u64)>>> {
		let offsetmaps = BTreeSet::<BTreeMap<u64, (u64, u64)>>::decode_directly(data)?;
		Ok(offsetmaps)
	}
}

impl HeaderCoding for VirtualObjectMap {
	type Item = VirtualObjectMap;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_VIRTUAL_OBJECT_MAP
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_VIRTUAL_OBJECT_MAP
	}
	
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![Self::version()];
		vec.append(&mut self.encode_content());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?; // check version (and skip it)
		let offsetmaps = Self::decode_inner_content(&mut cursor)?;

		Ok(Self::with_data(offsetmaps))
	}
}

// - implement fmt::Display
impl fmt::Display for VirtualObjectMap {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl VirtualObjectMap {
	fn struct_name(&self) -> &'static str {
		"VirtualObjectMap"
	}
}

impl Encryption for VirtualObjectMap {
	fn crypto_nonce_padding() -> u8 {
		0b01000000
	}
}