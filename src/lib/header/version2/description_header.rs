// - STD
use std::io::Cursor;

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	ZffErrorKind,
};
use crate::{
	HEADER_IDENTIFIER_DESCRIPTION_HEADER,
	ENCODING_KEY_CASE_NUMBER,
	ENCODING_KEY_EVIDENCE_NUMBER,
	ENCODING_KEY_EXAMINER_NAME,
	ENCODING_KEY_NOTES,
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
	case_number: Option<String>,
	evidence_number: Option<String>,
	examiner_name: Option<String>,
	notes: Option<String>,
}

impl DescriptionHeader {
	/// creates a new, empty header, which can be filled by the set_*-methods.
	/// All fields will be initialized with ```None``` or ```0```.
	pub fn new_empty(version: u8) -> DescriptionHeader {
		Self {
			version: version,
			case_number: None,
			evidence_number: None,
			examiner_name: None,
			notes: None,
		}
	}

	/// sets the case number as ```String```.
	pub fn set_case_number<V: Into<String>>(&mut self, value: V) {
		self.case_number = Some(value.into())
	}

	/// sets the evidence number as ```String```.
	pub fn set_evidence_number<V: Into<String>>(&mut self, value: V) {
		self.evidence_number = Some(value.into())
	}

	/// sets the examiner name as ```String```.
	pub fn set_examiner_name<V: Into<String>>(&mut self, value: V) {
		self.examiner_name = Some(value.into())
	}

	/// sets some notes as ```String```.
	pub fn set_notes<V: Into<String>>(&mut self, value: V) {
		self.notes = Some(value.into())
	}

	/// returns the case number, if available.
	pub fn case_number(&self) -> Option<&str> {
		match &self.case_number {
			Some(x) => Some(x),
			None => None
		}
	}

	/// returns the evidence number, if available.
	pub fn evidence_number(&self) -> Option<&str> {
		match &self.evidence_number {
			Some(x) => Some(x),
			None => None
		}
	}

	/// returns the examiner name, if available.
	pub fn examiner_name(&self) -> Option<&str> {
		match &self.examiner_name {
			Some(x) => Some(x),
			None => None
		}
	}

	/// returns the notes, if some available.
	pub fn notes(&self) -> Option<&str> {
		match &self.notes {
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
		if let Some(case_number) = self.case_number() {
			vec.append(&mut case_number.encode_for_key(ENCODING_KEY_CASE_NUMBER));
		};
		if let Some(evidence_number) = self.evidence_number() {
			vec.append(&mut evidence_number.encode_for_key(ENCODING_KEY_EVIDENCE_NUMBER));
		};
		if let Some(examiner_name) = self.examiner_name() {
			vec.append(&mut examiner_name.encode_for_key(ENCODING_KEY_EXAMINER_NAME));
		};
		if let Some(notes) = self.notes() {
			vec.append(&mut notes.encode_for_key(ENCODING_KEY_NOTES));
		};
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<DescriptionHeader> {
		let mut cursor = Cursor::new(data);
		let version = u8::decode_directly(&mut cursor)?;
		
		let mut description_header = DescriptionHeader::new_empty(version);

		let position = cursor.position();
		match String::decode_for_key(&mut cursor, ENCODING_KEY_CASE_NUMBER) {
			Ok(value) => description_header.set_case_number(value),
			Err(e) => match e.get_kind() {
				ZffErrorKind::HeaderDecoderKeyNotOnPosition => cursor.set_position(position),
				_ => return Err(e)
			},
		}
		let position = cursor.position();
		match String::decode_for_key(&mut cursor, ENCODING_KEY_EVIDENCE_NUMBER) {
			Ok(value) => description_header.set_evidence_number(value),
			Err(e) => match e.get_kind() {
				ZffErrorKind::HeaderDecoderKeyNotOnPosition => cursor.set_position(position),
				_ => return Err(e)
			},
		}
		let position = cursor.position();
		match String::decode_for_key(&mut cursor, ENCODING_KEY_EXAMINER_NAME) {
			Ok(value) => description_header.set_examiner_name(value),
			Err(e) => match e.get_kind() {
				ZffErrorKind::HeaderDecoderKeyNotOnPosition => cursor.set_position(position),
				_ => return Err(e)
			},
		}
		let position = cursor.position();
		match String::decode_for_key(&mut cursor, ENCODING_KEY_NOTES) {
			Ok(value) => description_header.set_notes(value),
			Err(e) => match e.get_kind() {
				ZffErrorKind::HeaderDecoderKeyNotOnPosition => cursor.set_position(position),
				_ => return Err(e)
			},
		}

		Ok(description_header)
	}
}