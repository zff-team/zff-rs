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
	ENCODING_KEY_SYSTEM_DATE,
};

pub struct DescriptionHeader {
	header_version: u8,
	case_number: Option<String>,
	evidence_number: Option<String>,
	examiner_name: Option<String>,
	notes: Option<String>,
	acquisition_date: Option<u32>,
	system_date: Option<u32>
}

impl DescriptionHeader {
	pub fn new(header_version: u8) -> DescriptionHeader {
		Self {
			header_version: header_version,
			case_number: None,
			evidence_number: None,
			examiner_name: None,
			notes: None,
			acquisition_date: None,
			system_date: None,
		}
	}
	pub fn header_version(&self) -> &u8 {
		&self.header_version
	}
	pub fn case_number(&self) -> Option<&str> {
		match &self.case_number {
			Some(x) => Some(x),
			None => None
		}
	}
	pub fn evidence_number(&self) -> Option<&str> {
		match &self.evidence_number {
			Some(x) => Some(x),
			None => None
		}
	}
	pub fn examiner_name(&self) -> Option<&str> {
		match &self.examiner_name {
			Some(x) => Some(x),
			None => None
		}
	}
	pub fn notes(&self) -> Option<&str> {
		match &self.notes {
			Some(x) => Some(x),
			None => None
		}
	}
	pub fn acquisition_date(&self) -> Option<u32> {
		match &self.acquisition_date {
			Some(x) => Some(*x),
			None => None
		}
	}
	pub fn system_date(&self) -> Option<u32> {
		match &self.system_date {
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
		if let Some(evidence_number) = self.case_number() {
			vec.append(&mut evidence_number.encode_for_key(ENCODING_KEY_EVIDENCE_NUMBER));
		};
		if let Some(examiner_name) = self.case_number() {
			vec.append(&mut examiner_name.encode_for_key(ENCODING_KEY_EXAMINER_NAME));
		};
		if let Some(notes) = self.case_number() {
			vec.append(&mut notes.encode_for_key(ENCODING_KEY_NOTES));
		};
		if let Some(acquisition_date) = self.case_number() {
			vec.append(&mut acquisition_date.encode_for_key(ENCODING_KEY_ACQISITION_DATE));
		};
		if let Some(system_date) = self.case_number() {
			vec.append(&mut system_date.encode_for_key(ENCODING_KEY_SYSTEM_DATE));
		};
		vec
	}
}

impl HeaderEncoder for DescriptionHeader {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_header = self.encode_header();
		let identifier = Self::identifier();
		let encoded_header_length = encoded_header.len() as u32;
		
		vec.push(ValueType::Object.as_raw_value());
		vec.append(&mut identifier.to_le_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.append(&mut encoded_header);

		vec
	}
}