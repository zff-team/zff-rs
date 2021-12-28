// - STD
use std::io::Cursor;
use std::fmt;

// - external
use serde::{Serialize};

// - internal
use crate::{
	Result,
	HeaderCoding,
	HEADER_IDENTIFIER_OBJECT_HEADER,
	ValueEncoder,
	ValueDecoder,
	ZffError,
	ZffErrorKind,
};

use crate::version2::header::{
	DescriptionHeader,
};

#[derive(Debug,Clone)]
pub struct ObjectHeader {
	version: u8,
	object_number: u64,
	description_header: DescriptionHeader,
	object_type: ObjectType
}

impl ObjectHeader {
	pub fn new(version: u8, object_number: u64, description_header: DescriptionHeader, object_type: ObjectType) -> ObjectHeader {
		Self {
			version: version,
			object_number: object_number,
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
	
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(self.version);
		vec.append(&mut self.object_number.encode_directly());
		vec.append(&mut self.description_header.encode_directly());
		vec.push(self.object_type.clone() as u8);
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<ObjectHeader> {
		let mut cursor = Cursor::new(data);
		let header_version = u8::decode_directly(&mut cursor)?;
		let object_number = u64::decode_directly(&mut cursor)?;
		let description_header = DescriptionHeader::decode_directly(&mut cursor)?;
		let object_type = match u8::decode_directly(&mut cursor)? {
			1 => ObjectType::Physical,
			2 => ObjectType::Logical,
			val @ _ => return Err(ZffError::new(ZffErrorKind::UnknownObjectTypeValue, val.to_string()))
		};

		Ok(ObjectHeader::new(header_version, object_number, description_header, object_type))
	}
}