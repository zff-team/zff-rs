// - STD
use std::io::Cursor;

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueDecoder,
	FOOTER_IDENTIFIER_OBJECT_FOOTER_PHYSICAL,
	FOOTER_IDENTIFIER_OBJECT_FOOTER_LOGICAL,
};
use crate::version2::header::{
	HashHeader,
};

#[derive(Debug,Clone)]
pub struct ObjectFooterPhysical {
	version: u8,
	hash_header: HashHeader,
}

impl ObjectFooterPhysical {
	pub fn new(version: u8, hash_header: HashHeader) -> ObjectFooterPhysical {
		Self {
			version: version,
			hash_header: hash_header,
		}
	}
}

impl HeaderCoding for ObjectFooterPhysical {
	type Item = ObjectFooterPhysical;
	fn version(&self) -> u8 { 
		self.version
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_OBJECT_FOOTER_PHYSICAL
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(self.version);
		vec.append(&mut self.hash_header.encode_directly());
		vec
	}
	fn decode_content(data: Vec<u8>) -> Result<ObjectFooterPhysical> {
		let mut cursor = Cursor::new(data);
		let footer_version = u8::decode_directly(&mut cursor)?;
		let hash_header = HashHeader::decode_directly(&mut cursor)?;
		Ok(ObjectFooterPhysical::new(footer_version, hash_header))
	}
}

#[derive(Debug,Clone)]
pub struct ObjectFooterLogical {
	version: u8,
}

impl ObjectFooterLogical {
	pub fn new(version: u8) -> ObjectFooterLogical {
		Self {
			version: version
		}
	}
}

impl HeaderCoding for ObjectFooterLogical {
	type Item = ObjectFooterLogical;

	fn version(&self) -> u8 { 
		self.version
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_OBJECT_FOOTER_LOGICAL
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(self.version);
		vec
	}
	fn decode_content(data: Vec<u8>) -> Result<ObjectFooterLogical> {
		let mut cursor = Cursor::new(data);
		let footer_version = u8::decode_directly(&mut cursor)?;
		Ok(ObjectFooterLogical::new(footer_version))
	}

}