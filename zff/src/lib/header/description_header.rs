// - internal
use crate::{
	HeaderObject,
	HeaderEncoder,
	ValueEncoder,
};
use crate::{
	HEADER_IDENTIFIER_DESCRIPTION_HEADER,
	ENCODING_KEY_CASE_NUMBER,
	ENCODING_KEY_EVIDENCE_NUMBER,
	ENCODING_KEY_EXAMINER_NAME,
	ENCODING_KEY_NOTES,
	ENCODING_KEY_ACQISITION_DATE,
};

/// The description header contains all data,
/// which describes the dumped data (e.g. case number, examiner name or acquisition date).\
/// This header is part of the main header and has the following layout:
/// 
/// |                | Magic bytes    | Header length | header version | case number<br>\<OPTIONAL\> | evidence number<br>\<OPTIONAL\> | examiner name<br>\<OPTIONAL\> | notes<br>\<OPTIONAL\> | acqusition date<br>\<OPTIONAL\> |
/// |----------------|----------------|---------------|-----------------------------|---------------------------------|-------------------------------|-----------------------|---------------------------------|----------------|
/// | **size**       | 4 bytes        | 8 bytes       | 1 byte         | variable                    | variable                        | variable                      | variable              | 8 bytes                         |
/// | **type**       | 0x7A666664     | uint64        | uint8          | String                      | String                          | String                        | String                | uint64                          |
/// | **identifier** | -              | -             | -              | "cn"                        | "ev"                            | "ex"                          | "no"                  | "ad"                            |
///
/// The special thing about this header is that the contained values\
/// - are all optional except for the version.
/// - have a prefixed identifier, which is encoded with.
#[derive(Debug,Clone)]
pub struct DescriptionHeader {
	header_version: u8,
	case_number: Option<String>,
	evidence_number: Option<String>,
	examiner_name: Option<String>,
	notes: Option<String>,
	acquisition_date: Option<u64>,
}

impl DescriptionHeader {
	/// creates a new - empty - header, which can be filled by the set_*-methods.
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

	/// returns the version of the header.
	pub fn header_version(&self) -> &u8 {
		&self.header_version
	}

	/// sets the case number as ```String```.
	pub fn set_case_number<V: Into<String>>(&mut self, value: V) {
		self.case_number = Some(value.into())
	}

	/// returns the case number, if available.
	pub fn case_number(&self) -> Option<&str> {
		match &self.case_number {
			Some(x) => Some(x),
			None => None
		}
	}

	/// sets the evidence number as ```String```.
	pub fn set_evidence_number<V: Into<String>>(&mut self, value: V) {
		self.evidence_number = Some(value.into())
	}

	/// returns the evidence number, if available
	pub fn evidence_number(&self) -> Option<&str> {
		match &self.evidence_number {
			Some(x) => Some(x),
			None => None
		}
	}

	/// sets the examiner name as ```String```.
	pub fn set_examiner_name<V: Into<String>>(&mut self, value: V) {
		self.examiner_name = Some(value.into())
	}

	/// returns the examiner name, if available.
	pub fn examiner_name(&self) -> Option<&str> {
		match &self.examiner_name {
			Some(x) => Some(x),
			None => None
		}
	}

	/// sets some notes as ```String```.
	pub fn set_notes<V: Into<String>>(&mut self, value: V) {
		self.notes = Some(value.into())
	}

	/// returns the notes, if some available.
	pub fn notes(&self) -> Option<&str> {
		match &self.notes {
			Some(x) => Some(x),
			None => None
		}
	}

	/// sets the acquisition date, as u64 unix timestamp.
	pub fn set_acquisition_date(&mut self, value: u64) {
		self.acquisition_date = Some(value)
	}

	/// returns the acquisition date, if available - as u64 unix timestamp.
	pub fn acquisition_date(&self) -> Option<u64> {
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

impl HeaderEncoder for DescriptionHeader {}