// - STD
use core::borrow::Borrow;
use std::io::{Cursor, Read};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::any::Any;

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueDecoder,
	ValueEncoder,
	Encryption,
	ZffError,
	ZffErrorKind,
};

use crate::{
	encryption::EncryptionAlgorithm,
	DEFAULT_LENGTH_HEADER_IDENTIFIER,
	DEFAULT_LENGTH_VALUE_HEADER_LENGTH,
	HEADER_IDENTIFIER_FILE_HEADER,
	ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER,
	DEFAULT_HEADER_VERSION_FILE_HEADER,
	METADATA_EXT_TYPE_IDENTIFIER_U8,
	METADATA_EXT_TYPE_IDENTIFIER_U16,
	METADATA_EXT_TYPE_IDENTIFIER_U32,
	METADATA_EXT_TYPE_IDENTIFIER_U64,
	METADATA_EXT_TYPE_IDENTIFIER_I8,
	METADATA_EXT_TYPE_IDENTIFIER_I16,
	METADATA_EXT_TYPE_IDENTIFIER_I32,
	METADATA_EXT_TYPE_IDENTIFIER_I64,
	METADATA_EXT_TYPE_IDENTIFIER_STRING,
	METADATA_EXT_TYPE_IDENTIFIER_HASHMAP,
	METADATA_EXT_TYPE_IDENTIFIER_BTREEMAP,
	METADATA_EXT_TYPE_IDENTIFIER_BYTEARRAY,
	METADATA_EXT_TYPE_IDENTIFIER_F32,
	METADATA_EXT_TYPE_IDENTIFIER_F64,
	METADATA_EXT_TYPE_IDENTIFIER_VEC,
	METADATA_EXT_TYPE_IDENTIFIER_BOOL,
};

use crate::header::EncryptionInformation;

// - external
use ordered_float::OrderedFloat;
#[cfg(feature = "serde")]
use serde::{
	Deserialize,
	Serialize,
	ser::{Serializer, SerializeMap, SerializeSeq},
};

/// Defines all file types, which are implemented for zff files.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq,Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum FileType {
	/// Represents a regular file (e.g. like "textfile.txt").
	File = 1,
	/// Represents a directory.
	Directory = 2,
	/// Represents a symbolic link.
	Symlink = 3,
	/// Represents a hard link (mostly used at unix like operating systems).
	Hardlink = 4,
	/// Represents a special file (like a FIFO, a char or block device).
	SpecialFile = 5,
}

impl fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let msg = match self {
			FileType::File => "File",
			FileType::Directory => "Directory",
			FileType::Symlink => "Symlink",
			FileType::Hardlink => "Hardlink",
			FileType::SpecialFile => "SpecialFile",
		};
		write!(f, "{}", msg)
	}
}

/// Defines all unix special file types
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq,Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum SpecialFileType {
	/// Represents a Fifo.
	Fifo = 0,
	/// Represents a char device.
	Char = 1,
	/// Represents a block device.
	Block = 2,
}

impl TryFrom<u8> for SpecialFileType {
	type Error = ZffError;
	fn try_from(byte: u8) -> Result<Self> {
		match byte {
			0 => Ok(SpecialFileType::Fifo),
			1 => Ok(SpecialFileType::Char),
			2 => Ok(SpecialFileType::Block),
			_ => Err(ZffError::new(ZffErrorKind::UnknownFileType, byte.to_string())),
		}
	}
}

impl TryFrom<&u8> for SpecialFileType {
	type Error = ZffError;
	fn try_from(byte: &u8) -> Result<Self> {
		match byte {
			0 => Ok(SpecialFileType::Fifo),
			1 => Ok(SpecialFileType::Char),
			2 => Ok(SpecialFileType::Block),
			_ => Err(ZffError::new(ZffErrorKind::UnknownFileType, byte.to_string())),
		}
	}
}

impl fmt::Display for SpecialFileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let msg = match self {
			SpecialFileType::Fifo => "Fifo",
			SpecialFileType::Char => "Char",
			SpecialFileType::Block => "Block",
		};
		write!(f, "{}", msg)
	}
}

/// Each dumped file* contains a [FileHeader] containing several metadata.
/// The following metadata are included in a [FileHeader]:
/// - the internal file number of the appropriate file.
/// - the [FileType] of the appropriate file.
/// - the original filename of the appropriate file **without** the full path (just the filename, e.g. "my_texfile.txt" or "my_directory")
/// - the file number of the parent directory of this file (if the file lies into the root directory, this is 0 because the first valid file number in zff is 1).
/// - A HashMap to extend the metadata based on the operating system/filesystem. Some fields are predefined, see [the full list in the wiki](https://github.com/ph0llux/zff/wiki/zff-header-layout#file-metadata-extended-information)
#[derive(Debug,Clone,Eq,PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct FileHeader {
	/// The appropriate filenumber.
	pub file_number: u64,
	/// The appropriate filetype.
	pub file_type: FileType,
	/// The appropriate filename. 
	pub filename: String,
	/// The parent file number of this file. Will be 0, if the parent is the root directory.
	pub parent_file_number: u64,
	/// A [HashMap] of the metadata of this file. The keys are the names of the metadata and the values are the values of the metadata.
	pub metadata_ext: HashMap<String, MetadataExtendedValue>,
}

impl FileHeader {
	/// creates a new [FileHeader] with the given values.
	pub fn new<F: Into<String>>(
		file_number: u64,
		file_type: FileType,
		filename: F,
		parent_file_number: u64,
		metadata_ext: HashMap<String, MetadataExtendedValue>) -> FileHeader {
		Self {
			file_number,
			file_type,
			filename: filename.into(),
			parent_file_number,
			metadata_ext
		}
	}

	/// transforms the inner [FileType] to a [FileType::Hardlink]. This does not work with a [FileType::Symlink]!
	pub fn transform_to_hardlink(&mut self) {
		if self.file_type != FileType::Symlink {
			self.file_type = FileType::Hardlink
		}
	}

	/// encodes the file header to a ```Vec<u8>```. The encryption flag of the appropriate object header has to be set to 2.
	/// # Error
	/// The method returns an error, if the encryption fails.
	pub fn encode_encrypted_header_directly<E>(&self, encryption_information: E) -> Result<Vec<u8>>
	where
		E: Borrow<EncryptionInformation>
	{
		let mut vec = Vec::new();
		let encryption_information = encryption_information.borrow();
		let mut encoded_header = self.encode_encrypted_header(&encryption_information.encryption_key, &encryption_information.algorithm)?;
		let identifier = HEADER_IDENTIFIER_FILE_HEADER;
		let encoded_header_length = 4 + 8 + (encoded_header.len() as u64); //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.append(&mut encoded_header);

		Ok(vec)
	}

	fn encode_encrypted_header<K, A>(&self, key: K, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		let mut vec = Vec::new();
		vec.append(&mut Self::version().encode_directly());
		vec.append(&mut self.file_number.encode_directly());

		let mut data_to_encrypt = Vec::new();
		data_to_encrypt.append(&mut self.encode_content());

		let encrypted_data = FileHeader::encrypt(
			key, data_to_encrypt,
			self.file_number,
			algorithm
			)?;
		vec.append(&mut encrypted_data.encode_directly());
		Ok(vec)
	}

	fn encode_content(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut (self.file_type.clone() as u8).encode_directly());
		vec.append(&mut self.filename.encode_directly());
		vec.append(&mut self.parent_file_number.encode_directly());
		vec.append(&mut self.metadata_ext.encode_directly());
		vec
	}

	/// decodes the encrypted header with the given key and [crate::header::EncryptionHeader].
	/// The appropriate [crate::header::EncryptionHeader] has to be stored in the appropriate [crate::header::ObjectHeader].
	pub fn decode_encrypted_header_with_key<R, E>(data: &mut R, encryption_information: E) -> Result<FileHeader>
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
		Self::check_version(&mut cursor)?;
		let file_number = u64::decode_directly(&mut cursor)?;
		
		let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
		let algorithm = &encryption_information.borrow().algorithm;
		let decrypted_data = FileHeader::decrypt(
			&encryption_information.borrow().encryption_key, 
			encrypted_data, 
			file_number, 
			algorithm)?;
		let mut cursor = Cursor::new(decrypted_data);
		let (file_type,
			filename,
			parent_file_number,
			metadata_ext) = Self::decode_inner_content(&mut cursor)?;
		let file_header = Self::new(
			file_number,
			file_type,
			filename,
			parent_file_number,
			metadata_ext);
		Ok(file_header)
	}

	#[allow(clippy::type_complexity)]
	fn decode_inner_content<R: Read>(inner_content: &mut R) -> Result<(
		FileType,
		String, //Filename
		u64, //parent_file_number
		HashMap<String, MetadataExtendedValue>,
		)> {
		let file_type = match u8::decode_directly(inner_content)? {
			1 => FileType::File,
			2 => FileType::Directory,
			3 => FileType::Symlink,
			4 => FileType::Hardlink,
			val => return Err(ZffError::new(ZffErrorKind::UnknownFileType, val.to_string()))
		};
		let filename = String::decode_directly(inner_content)?;
		let parent_file_number = u64::decode_directly(inner_content)?;
		let metadata_ext = HashMap::<String, MetadataExtendedValue>::decode_directly(inner_content)?;
		let inner_content = (
			file_type,
			filename,
			parent_file_number,
			metadata_ext);
		Ok(inner_content)
	}
}

impl HeaderCoding for FileHeader {
	type Item = FileHeader;
	
	fn identifier() -> u32 {
		HEADER_IDENTIFIER_FILE_HEADER
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_FILE_HEADER
	}
	
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut Self::version().encode_directly());
		vec.append(&mut self.file_number.encode_directly());
		vec.append(&mut self.encode_content());
		vec
		
	}

	fn decode_content(data: Vec<u8>) -> Result<FileHeader> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?;
		let file_number = u64::decode_directly(&mut cursor)?;
		let (file_type, filename, parent_file_number, metadata_ext) = Self::decode_inner_content(&mut cursor)?;
		Ok(FileHeader::new(file_number, file_type, filename, parent_file_number, metadata_ext))
	}

	fn struct_name() -> &'static str {
		"FileHeader"
	}
}

// - implement fmt::Display
impl fmt::Display for FileHeader {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", Self::struct_name())
	}
}

impl Encryption for FileHeader {
	fn crypto_nonce_padding() -> u8 {
		0b00000100
	}
}

/// This is a wrapper enum for all possible values of the metadata extended values.
#[derive(Debug,Clone,Eq,PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub enum MetadataExtendedValue {
	/// represents a uint8 value
	U8(u8),
	/// represents a uint16 value
	U16(u16),
	/// represents a uint32 value
	U32(u32),
	/// represents a uint64 value
	U64(u64),
	/// represents a int8 value
	I8(i8),
	/// represents a int16 value
	I16(i16),
	/// represents a int32 value
	I32(i32),
	/// represents a int64 value
	I64(i64),
	/// represents a string value
	String(String),
	/// represents a hashmap value
	Hashmap(HashMap<String, MetadataExtendedValue>),
	/// represents a BTreeMap value
	BTreeMap(BTreeMap<String, MetadataExtendedValue>),
	/// represents a loose byte array
	ByteArray(Vec<u8>),
	/// represents a float32 value
	F32(OrderedFloat<f32>),
	/// represents a float64 value
	F64(OrderedFloat<f64>),
	/// represents a vector
	Vector(Vec<MetadataExtendedValue>),
	/// represents a bool value
	Bool(bool),
}

#[cfg(feature = "serde")]
impl Serialize for MetadataExtendedValue {
	fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match self {
			MetadataExtendedValue::U8(value) => serializer.serialize_u8(*value),
			MetadataExtendedValue::U16(value) => serializer.serialize_u16(*value),
			MetadataExtendedValue::U32(value) => serializer.serialize_u32(*value),
			MetadataExtendedValue::U64(value) => serializer.serialize_u64(*value),
			MetadataExtendedValue::I8(value) => serializer.serialize_i8(*value),
			MetadataExtendedValue::I16(value) => serializer.serialize_i16(*value),
			MetadataExtendedValue::I32(value) => serializer.serialize_i32(*value),
			MetadataExtendedValue::I64(value) => serializer.serialize_i64(*value),
			MetadataExtendedValue::String(value) => serializer.serialize_str(value),
			MetadataExtendedValue::Hashmap(value) => {
				let mut state = serializer.serialize_map(Some(value.len()))?;
				for (key, value) in value {
					state.serialize_entry(key, value)?;
				}
				state.end()
			},
			MetadataExtendedValue::BTreeMap(value) => {
				let mut state = serializer.serialize_map(Some(value.len()))?;
				for (key, value) in value {
					state.serialize_entry(key, value)?;
				}
				state.end()
			},
			MetadataExtendedValue::ByteArray(value) => serializer.serialize_bytes(value),
			MetadataExtendedValue::F32(value) => serializer.serialize_f32(value.into_inner()),
			MetadataExtendedValue::F64(value) => serializer.serialize_f64(value.into_inner()),
			MetadataExtendedValue::Vector(value) => {
				let mut state = serializer.serialize_seq(Some(value.len()))?;
				for value in value {
					state.serialize_element(value)?;
				}
				state.end()
			},
			MetadataExtendedValue::Bool(value) => serializer.serialize_bool(*value),
		}
	}
}

impl MetadataExtendedValue {
	/// returns the inner value.
	pub fn into_any(self) -> Box<dyn Any> {
		match self {
			MetadataExtendedValue::U8(value) => Box::new(value),
			MetadataExtendedValue::U16(value) => Box::new(value),
			MetadataExtendedValue::U32(value) => Box::new(value),
			MetadataExtendedValue::U64(value) => Box::new(value),
			MetadataExtendedValue::I8(value) => Box::new(value),
			MetadataExtendedValue::I16(value) => Box::new(value),
			MetadataExtendedValue::I32(value) => Box::new(value),
			MetadataExtendedValue::I64(value) => Box::new(value),
			MetadataExtendedValue::String(value) => Box::new(value),
			MetadataExtendedValue::Hashmap(value) => Box::new(value),
			MetadataExtendedValue::BTreeMap(value) => Box::new(value),
			MetadataExtendedValue::ByteArray(value) => Box::new(value),
			MetadataExtendedValue::F32(value) => Box::new(value),
			MetadataExtendedValue::F64(value) => Box::new(value),
			MetadataExtendedValue::Vector(value) => Box::new(value),
			MetadataExtendedValue::Bool(value) => Box::new(value),
		}
	}

	/// returns the inner value.
	pub fn as_any(&self) -> Box<&dyn Any> {
		match self {
			MetadataExtendedValue::U8(value) => Box::new(value),
			MetadataExtendedValue::U16(value) => Box::new(value),
			MetadataExtendedValue::U32(value) => Box::new(value),
			MetadataExtendedValue::U64(value) => Box::new(value),
			MetadataExtendedValue::I8(value) => Box::new(value),
			MetadataExtendedValue::I16(value) => Box::new(value),
			MetadataExtendedValue::I32(value) => Box::new(value),
			MetadataExtendedValue::I64(value) => Box::new(value),
			MetadataExtendedValue::String(value) => Box::new(value),
			MetadataExtendedValue::Hashmap(value) => Box::new(value),
			MetadataExtendedValue::BTreeMap(value) => Box::new(value),
			MetadataExtendedValue::ByteArray(value) => Box::new(value),
			MetadataExtendedValue::F32(value) => Box::new(value),
			MetadataExtendedValue::F64(value) => Box::new(value),
			MetadataExtendedValue::Vector(value) => Box::new(value),
			MetadataExtendedValue::Bool(value) => Box::new(value),
		}
	}
}

impl ValueEncoder for Vec<MetadataExtendedValue> {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		for value in self {
			vec.append(&mut value.encode_directly());
		}
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_VEC
	}

	fn encode_with_identifier(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(self.identifier());
		vec.append(&mut (self.len() as u64).encode_directly());
		for value in self {
			vec.append(&mut value.encode_with_identifier());
		}
		vec
	}
}

impl ValueEncoder for HashMap<String, MetadataExtendedValue> {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut (self.len() as u64).encode_directly());
		for (key, value) in self {
			vec.append(&mut key.encode_directly());
			vec.append(&mut value.encode_with_identifier());
		}
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_HASHMAP
	}

	fn encode_with_identifier(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(self.identifier());
		vec.append(&mut (self.len() as u64).encode_directly());
		for (key, value) in self {
			vec.append(&mut key.encode_directly());
			vec.append(&mut value.encode_with_identifier());
		}
		vec
	}
}

impl ValueEncoder for MetadataExtendedValue {
	fn encode_directly(&self) -> Vec<u8> {
		self.encode_with_identifier()
	}

	fn identifier(&self) -> u8 {
		match self {
			MetadataExtendedValue::U8(value) => value.identifier(),
			MetadataExtendedValue::U16(value) => value.identifier(),
			MetadataExtendedValue::U32(value) => value.identifier(),
			MetadataExtendedValue::U64(value) => value.identifier(),
			MetadataExtendedValue::I8(value) => value.identifier(),
			MetadataExtendedValue::I16(value) => value.identifier(),
			MetadataExtendedValue::I32(value) => value.identifier(),
			MetadataExtendedValue::I64(value) => value.identifier(),
			MetadataExtendedValue::String(value) => value.identifier(),
			MetadataExtendedValue::Hashmap(value) => value.identifier(),
			MetadataExtendedValue::BTreeMap(value) => value.identifier(),
			MetadataExtendedValue::ByteArray(value) => value.identifier(),
			MetadataExtendedValue::F32(value) => value.identifier(),
			MetadataExtendedValue::F64(value) => value.identifier(),
			MetadataExtendedValue::Vector(value) => value.identifier(),
			MetadataExtendedValue::Bool(value) => value.identifier(),
		}
	}

	fn encode_with_identifier(&self) -> Vec<u8> {
		match self {
			MetadataExtendedValue::U8(value) => value.encode_with_identifier(),
			MetadataExtendedValue::U16(value) => value.encode_with_identifier(),
			MetadataExtendedValue::U32(value) => value.encode_with_identifier(),
			MetadataExtendedValue::U64(value) => value.encode_with_identifier(),
			MetadataExtendedValue::I8(value) => value.encode_with_identifier(),
			MetadataExtendedValue::I16(value) => value.encode_with_identifier(),
			MetadataExtendedValue::I32(value) => value.encode_with_identifier(),
			MetadataExtendedValue::I64(value) => value.encode_with_identifier(),
			MetadataExtendedValue::String(value) => value.encode_with_identifier(),
			MetadataExtendedValue::Hashmap(value) => value.encode_with_identifier(),
			MetadataExtendedValue::BTreeMap(value) => value.encode_with_identifier(),
			MetadataExtendedValue::ByteArray(value) => value.encode_with_identifier(),
			MetadataExtendedValue::F32(value) => value.encode_with_identifier(),
			MetadataExtendedValue::F64(value) => value.encode_with_identifier(),
			MetadataExtendedValue::Vector(value) => value.encode_with_identifier(),
			MetadataExtendedValue::Bool(value) => value.encode_with_identifier(),
		}
	}
}

impl ValueDecoder for MetadataExtendedValue {
	type Item = MetadataExtendedValue;

	fn decode_directly<R: Read>(data: &mut R) -> Result<Self> {
		let identifier = u8::decode_directly(data)?;
		match identifier {
			METADATA_EXT_TYPE_IDENTIFIER_U8 => Ok(MetadataExtendedValue::U8(u8::decode_directly(data)?)),
			METADATA_EXT_TYPE_IDENTIFIER_U16 => Ok(MetadataExtendedValue::U16(u16::decode_directly(data)?)),
			METADATA_EXT_TYPE_IDENTIFIER_U32 => Ok(MetadataExtendedValue::U32(u32::decode_directly(data)?)),
			METADATA_EXT_TYPE_IDENTIFIER_U64 => Ok(MetadataExtendedValue::U64(u64::decode_directly(data)?)),
			METADATA_EXT_TYPE_IDENTIFIER_I8 => Ok(MetadataExtendedValue::I8(i8::decode_directly(data)?)),
			METADATA_EXT_TYPE_IDENTIFIER_I16 => Ok(MetadataExtendedValue::I16(i16::decode_directly(data)?)),
			METADATA_EXT_TYPE_IDENTIFIER_I32 => Ok(MetadataExtendedValue::I32(i32::decode_directly(data)?)),
			METADATA_EXT_TYPE_IDENTIFIER_I64 => Ok(MetadataExtendedValue::I64(i64::decode_directly(data)?)),
			METADATA_EXT_TYPE_IDENTIFIER_STRING => Ok(MetadataExtendedValue::String(String::decode_directly(data)?)),
			METADATA_EXT_TYPE_IDENTIFIER_HASHMAP => {
				let length = u64::decode_directly(data)?;
				let mut hashmap = HashMap::new();
				for _ in 0..length {
					let key = String::decode_directly(data)?;
					let value = MetadataExtendedValue::decode_directly(data)?;
					hashmap.insert(key, value);
				}
				Ok(MetadataExtendedValue::Hashmap(hashmap))
			},
			METADATA_EXT_TYPE_IDENTIFIER_BTREEMAP => {
				let length = u64::decode_directly(data)?;
				let mut btreemap = BTreeMap::new();
				for _ in 0..length {
					let key = String::decode_directly(data)?;
					let value = MetadataExtendedValue::decode_directly(data)?;
					btreemap.insert(key, value);
				}
				Ok(MetadataExtendedValue::BTreeMap(btreemap))
			},
			METADATA_EXT_TYPE_IDENTIFIER_BYTEARRAY => Ok(MetadataExtendedValue::ByteArray(Vec::<u8>::decode_directly(data)?)),
			METADATA_EXT_TYPE_IDENTIFIER_F32 => Ok(MetadataExtendedValue::F32(OrderedFloat::from(f32::decode_directly(data)?))),
			METADATA_EXT_TYPE_IDENTIFIER_F64 => Ok(MetadataExtendedValue::F64(OrderedFloat::from(f64::decode_directly(data)?))),
			METADATA_EXT_TYPE_IDENTIFIER_VEC => {
				let length = u64::decode_directly(data)?;
				let mut vec = Vec::new();
				for _ in 0..length {
					vec.push(MetadataExtendedValue::decode_directly(data)?);
				}
				Ok(MetadataExtendedValue::Vector(vec))
			},
			METADATA_EXT_TYPE_IDENTIFIER_BOOL => Ok(MetadataExtendedValue::Bool(bool::decode_directly(data)?)),
			_ => Err(ZffError::new(ZffErrorKind::UnknownMetadataExtendedType, identifier.to_string())),
		}
	}
}

impl From<u8> for MetadataExtendedValue {
	fn from(value: u8) -> Self {
		MetadataExtendedValue::U8(value)
	}
}

impl From<&u8> for MetadataExtendedValue {
	fn from(value: &u8) -> Self {
		MetadataExtendedValue::U8(*value)
	}
}

impl From<u16> for MetadataExtendedValue {
	fn from(value: u16) -> Self {
		MetadataExtendedValue::U16(value)
	}
}

impl From<&u16> for MetadataExtendedValue {
	fn from(value: &u16) -> Self {
		MetadataExtendedValue::U16(*value)
	}
}

impl From<u32> for MetadataExtendedValue {
	fn from(value: u32) -> Self {
		MetadataExtendedValue::U32(value)
	}
}

impl From<&u32> for MetadataExtendedValue {
	fn from(value: &u32) -> Self {
		MetadataExtendedValue::U32(*value)
	}
}

impl From<u64> for MetadataExtendedValue {
	fn from(value: u64) -> Self {
		MetadataExtendedValue::U64(value)
	}
}

impl From<&u64> for MetadataExtendedValue {
	fn from(value: &u64) -> Self {
		MetadataExtendedValue::U64(*value)
	}
}

impl From<i8> for MetadataExtendedValue {
	fn from(value: i8) -> Self {
		MetadataExtendedValue::I8(value)
	}
}

impl From<&i8> for MetadataExtendedValue {
	fn from(value: &i8) -> Self {
		MetadataExtendedValue::I8(*value)
	}
}

impl From<i16> for MetadataExtendedValue {
	fn from(value: i16) -> Self {
		MetadataExtendedValue::I16(value)
	}
}

impl From<&i16> for MetadataExtendedValue {
	fn from(value: &i16) -> Self {
		MetadataExtendedValue::I16(*value)
	}
}

impl From<i32> for MetadataExtendedValue {
	fn from(value: i32) -> Self {
		MetadataExtendedValue::I32(value)
	}
}

impl From<&i32> for MetadataExtendedValue {
	fn from(value: &i32) -> Self {
		MetadataExtendedValue::I32(*value)
	}
}

impl From<i64> for MetadataExtendedValue {
	fn from(value: i64) -> Self {
		MetadataExtendedValue::I64(value)
	}
}

impl From<&i64> for MetadataExtendedValue {
	fn from(value: &i64) -> Self {
		MetadataExtendedValue::I64(*value)
	}
}

impl From<String> for MetadataExtendedValue {
	fn from(value: String) -> Self {
		MetadataExtendedValue::String(value)
	}
}

impl From<&str> for MetadataExtendedValue {
	fn from(value: &str) -> Self {
		MetadataExtendedValue::String(value.to_string())
	}
}

impl From<Vec<u8>> for MetadataExtendedValue {
	fn from(value: Vec<u8>) -> Self {
		MetadataExtendedValue::ByteArray(value)
	}
}

impl From<&[u8]> for MetadataExtendedValue {
	fn from(value: &[u8]) -> Self {
		MetadataExtendedValue::ByteArray(value.to_vec())
	}
}

impl From<f32> for MetadataExtendedValue {
	fn from(value: f32) -> Self {
		MetadataExtendedValue::F32(OrderedFloat::from(value))
	}
}

impl From<f64> for MetadataExtendedValue {
	fn from(value: f64) -> Self {
		MetadataExtendedValue::F64(OrderedFloat::from(value))
	}
}