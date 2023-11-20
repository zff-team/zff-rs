// - STD
use std::io::Cursor;
use std::io::Read;
use std::collections::HashMap;
use std::fmt;

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	ZffError,
	ZffErrorKind,
};

#[cfg(feature = "serde")]
use crate::helper::string_to_str;

use crate::{
	HEADER_IDENTIFIER_DESCRIPTION_HEADER,
	ENCODING_KEY_CASE_NUMBER,
	ENCODING_KEY_EVIDENCE_NUMBER,
	ENCODING_KEY_EXAMINER_NAME,
	ENCODING_KEY_NOTES,
	constants::*,
};

// - external
#[cfg(feature = "serde")]
use serde::{
	ser::{
		Serialize,
		Serializer,
		SerializeStruct,
	},
	Deserialize,
};

/// The description header contains all data,
/// which describes the dumped data in den appropriate object (e.g. case number, examiner name or acquisition date).\
/// The description information are stored in a HashMap (e.g. like ["acquisition tool", "zffacquire"]).
/// Some fields are predefined, to be able to ensure a certain degree of compatibility between different tools.
/// The following fields are predefined:
/// - case number (for the appropriate HashMap key, see [ENCODING_KEY_CASE_NUMBER](crate::constants::ENCODING_KEY_CASE_NUMBER))
/// - evidence number (for the appropriate HashMap key, see [ENCODING_KEY_EVIDENCE_NUMBER](crate::constants::ENCODING_KEY_EVIDENCE_NUMBER))
/// - examiner name (for the appropriate HashMap key, see [ENCODING_KEY_EXAMINER_NAME](crate::constants::ENCODING_KEY_EXAMINER_NAME))
/// - notes ((for the appropriate HashMap key, see [ENCODING_KEY_NOTES](crate::constants::ENCODING_KEY_NOTES))
/// 
/// But you are free to define custom additional key-value pairs.
/// 
/// # Example
/// ```
/// use zff::header::DescriptionHeader;
/// 
/// let header_version = 2;
/// let mut description_header = DescriptionHeader::new_empty(header_version);
/// 
/// description_header.set_examiner_name("ph0llux");
/// assert_eq!(Some("ph0llux"), description_header.examiner_name());
/// ```
#[derive(Debug,Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct DescriptionHeader {
	version: u8,
	identifier_map: HashMap<String, String>
}

#[cfg(feature = "serde")]
impl Serialize for DescriptionHeader {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct(self.struct_name(), self.identifier_map.keys().len()+1)?;
        state.serialize_field("version", &self.version)?;
        for (key, value) in &self.identifier_map {
        	//work around lifetime checking (there is maybe a more elegant solution...)
        	state.serialize_field(string_to_str(key.to_string()), string_to_str(value.to_string()))?;
        }
        state.end()
    }
}

impl DescriptionHeader {
	/// creates a new, empty header, which can be filled by the set_*-methods.
	/// All fields will be initialized with ```None``` or ```0```.
	pub fn new_empty(version: u8) -> DescriptionHeader {
		Self {
			version,
			identifier_map: HashMap::new(),
		}
	}

	/// Creates a new [DescriptionHeader] with the given identifier map.
	pub fn new(version: u8, identifier_map: HashMap<String, String>) -> DescriptionHeader {
		Self {
			version,
			identifier_map,
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

	/// inserts a custom key-value pair
	pub fn custom_identifier_value<K: Into<String>, V: Into<String>>(&mut self, key: K, value: V) {
		self.identifier_map.insert(key.into(), value.into());
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

	/// returns all key-value pairs of this header.
	pub fn identifier_map(&self) -> &HashMap<String, String> {
		&self.identifier_map
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
		vec.append(&mut self.version.encode_directly());
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
		Self::decode_content(header_content)
	}

	fn decode_content(data: Vec<u8>) -> Result<DescriptionHeader> {
		let mut cursor = Cursor::new(data);
		let version = u8::decode_directly(&mut cursor)?;
		let identifier_map = HashMap::<String, String>::decode_directly(&mut cursor)?;
		let description_header = DescriptionHeader::new(version, identifier_map);

		Ok(description_header)
	}
}

// - implement fmt::Display
impl fmt::Display for DescriptionHeader {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl DescriptionHeader {
	fn struct_name(&self) -> &'static str {
		"DescriptionHeader"
	}
}