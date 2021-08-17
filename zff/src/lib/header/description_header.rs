// - internal
use crate::{
	HeaderObject,
	HeaderEncoder,
	ValueType,
};
use crate::{
	HEADER_IDENTIFIER_DESCRIPTION_HEADER,
	ENCODING_KEY_CASE_NUMBER,
	ENCODING_KEY_EVIDENCE_NUMBER,
	ENCODING_KEY_EXAMINER_NAME,
	ENCODING_KEY_NOTES,
	ENCODING_KEY_ACQISITION_DATE,
};

#[derive(Debug,Clone)]
pub struct DescriptionHeader {
	header_version: u8,
	case_number: Option<String>,
	evidence_number: Option<String>,
	examiner_name: Option<String>,
	notes: Option<String>,
	acquisition_date: Option<u32>,
}

impl DescriptionHeader {
	pub fn new_empty(header_version: u8) -> DescriptionHeader {
		Self {
			header_version: header_version,
			case_number: None,
			evidence_number: None,
			examiner_name: None,
			notes: None,
			acquisition_date: None,
		}
	}
	pub fn header_version(&self) -> &u8 {
		&self.header_version
	}

	pub fn set_case_number<V: Into<String>>(&mut self, value: V) {
		self.case_number = Some(value.into())
	}
	pub fn case_number(&self) -> Option<&str> {
		match &self.case_number {
			Some(x) => Some(x),
			None => None
		}
	}

	pub fn set_evidence_number<V: Into<String>>(&mut self, value: V) {
		self.evidence_number = Some(value.into())
	}
	pub fn evidence_number(&self) -> Option<&str> {
		match &self.evidence_number {
			Some(x) => Some(x),
			None => None
		}
	}

	pub fn set_examiner_name<V: Into<String>>(&mut self, value: V) {
		self.examiner_name = Some(value.into())
	}
	pub fn examiner_name(&self) -> Option<&str> {
		match &self.examiner_name {
			Some(x) => Some(x),
			None => None
		}
	}

	pub fn set_notes<V: Into<String>>(&mut self, value: V) {
		self.notes = Some(value.into())
	}
	pub fn notes(&self) -> Option<&str> {
		match &self.notes {
			Some(x) => Some(x),
			None => None
		}
	}

	pub fn set_acquisition_date(&mut self, value: u32) {
		self.acquisition_date = Some(value)
	}
	pub fn acquisition_date(&self) -> Option<u32> {
		match &self.acquisition_date {
			Some(x) => Some(*x),
			None => None
		}
	}
}

impl HeaderObject for DescriptionHeader {
	fn identifier() -> u32 {
		HEADER_IDENTIFIER_DESCRIPTION_HEADER
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.push(self.header_version);
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
		if let Some(acquisition_date) = self.acquisition_date() {
			vec.append(&mut acquisition_date.encode_for_key(ENCODING_KEY_ACQISITION_DATE));
		};
		vec
	}
}

impl HeaderEncoder for DescriptionHeader {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_header = self.encode_header();
		let identifier = Self::identifier();
		let encoded_header_length = 4 + 8 + (encoded_header.len() as u64); //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.append(&mut encoded_header);

		vec
	}
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = Self::encode_key(key);
		vec.append(&mut encoded_key);
		vec.push(ValueType::Object.clone() as u8);
		vec.append(&mut self.encode_directly());
		vec
	}
}