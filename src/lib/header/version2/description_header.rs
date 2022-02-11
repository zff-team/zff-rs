// - STD
use std::io::Cursor;
use std::io::Read;
use std::collections::HashMap;

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	ZffError,
	ZffErrorKind,
};
use crate::{
	HEADER_IDENTIFIER_DESCRIPTION_HEADER,
	ENCODING_KEY_CASE_NUMBER,
	ENCODING_KEY_EVIDENCE_NUMBER,
	ENCODING_KEY_EXAMINER_NAME,
	ENCODING_KEY_NOTES,
	constants::*,
};

/// The description header contains all data,
/// which describes the dumped data (e.g. case number, examiner name or acquisition date).\
/// This header is part of the main header.
/// The special thing about this header is that the contained values\
/// - are all optional except for the version.\
/// - have a prefixed identifier, which is encoded with.
/// # Example
/// ```
/// use zff::header::DescriptionHeader;
/// 
/// fn main() {
/// 	let header_version = 1;
/// 	let mut description_header = DescriptionHeader::new_empty(1);
/// 
/// 	description_header.set_examiner_name("ph0llux");
/// 	assert_eq!(Some("ph0llux"), description_header.examiner_name());
/// }
/// ```
#[derive(Debug,Clone)]
pub struct DescriptionHeader {
	version: u8,
	identifier_map: HashMap<String, String>
}

impl DescriptionHeader {
	/// creates a new, empty header, which can be filled by the set_*-methods.
	/// All fields will be initialized with ```None``` or ```0```.
	pub fn new_empty(version: u8) -> DescriptionHeader {
		Self {
			version: version,
			identifier_map: HashMap::new(),
		}
	}

	pub fn new(version: u8, identifier_map: HashMap<String, String>) -> DescriptionHeader {
		Self {
			version: version,
			identifier_map: identifier_map,
		}
	}

	/// sets the case number as ```String```.
	pub fn set_case_number<V: Into<String>>(&mut self, value: V) {
		self.identifier_map.insert(String::from(ENCODING_KEY_CASE_NUMBER), value.into());
	}

	/// sets the evidence number as ```String```.
	pub fn set_evidence_number<V: Into<String>>(&mut self, value: V) {
		self.identifier_map.insert(String::from(ENCODING_KEY_EVIDENCE_NUMBER), value.into());
	}

	/// sets the examiner name as ```String```.
	pub fn set_examiner_name<V: Into<String>>(&mut self, value: V) {
		self.identifier_map.insert(String::from(ENCODING_KEY_EXAMINER_NAME), value.into());
	}

	/// sets some notes as ```String```.
	pub fn set_notes<V: Into<String>>(&mut self, value: V) {
		self.identifier_map.insert(String::from(ENCODING_KEY_NOTES), value.into());
	}

	/// returns the case number, if available.
	pub fn case_number(&self) -> Option<&str> {
		match &self.identifier_map.get(ENCODING_KEY_CASE_NUMBER) {
			Some(x) => Some(x),
			None => None
		}
	}

	/// returns the evidence number, if available.
	pub fn evidence_number(&self) -> Option<&str> {
		match &self.identifier_map.get(ENCODING_KEY_EVIDENCE_NUMBER) {
			Some(x) => Some(x),
			None => None
		}
	}

	/// returns the examiner name, if available.
	pub fn examiner_name(&self) -> Option<&str> {
		match &self.identifier_map.get(ENCODING_KEY_EXAMINER_NAME) {
			Some(x) => Some(x),
			None => None
		}
	}

	/// returns the notes, if some available.
	pub fn notes(&self) -> Option<&str> {
		match &self.identifier_map.get(ENCODING_KEY_NOTES) {
			Some(x) => Some(x),
			None => None
		}
	}
}

impl HeaderCoding for DescriptionHeader {
	type Item = DescriptionHeader;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_DESCRIPTION_HEADER
	}

	fn version(&self) -> u8 {
		self.version
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(self.version);
		vec.append(&mut self.identifier_map.encode_directly());
		vec
	}

	/// decodes the header directly.
	fn decode_directly<R: Read>(data: &mut R) -> Result<Self::Item> {
		if !Self::check_identifier(data) {
			return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER));
		}
		let header_length = Self::decode_header_length(data)? as usize;
		let mut header_content = vec![0u8; header_length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
		data.read_exact(&mut header_content)?;
		return Self::decode_content(header_content);
	}

	fn decode_content(data: Vec<u8>) -> Result<DescriptionHeader> {
		let mut cursor = Cursor::new(data);
		let version = u8::decode_directly(&mut cursor)?;
		let identifier_map = HashMap::<String, String>::decode_directly(&mut cursor)?;
		let description_header = DescriptionHeader::new(version, identifier_map);

		Ok(description_header)
	}
}