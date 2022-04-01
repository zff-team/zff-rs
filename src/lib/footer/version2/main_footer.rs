// - STD
use std::io::Cursor;
use std::collections::HashMap;

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueDecoder,
	ValueEncoder,
	ZffErrorKind,
	FOOTER_IDENTIFIER_MAIN_FOOTER,
	ENCODING_KEY_DESCRIPTION_NOTES,
};

/// The main footer is the last thing, which is written at the end of the last segment.\
/// This footer contains a lot of variable information about the zff container (e.g. number of segments, ...).
#[derive(Debug,Clone)]
pub struct MainFooter {
	version: u8,
	number_of_segments: u64,
	object_header: HashMap<u64, u64>, // <object number, segment number>
	object_footer: HashMap<u64, u64>, // <object number, segment number>
	description_notes: Option<String>,
	/// offset in the current segment, where the footer starts.
	footer_offset: u64,
}

impl MainFooter {
	/// creates a new MainFooter with a given values.
	pub fn new(version: u8, number_of_segments: u64, object_header: HashMap<u64, u64>, object_footer: HashMap<u64, u64>, description_notes: Option<String>, footer_offset: u64) -> MainFooter {
		Self {
			version: version,
			number_of_segments: number_of_segments,
			object_header: object_header,
			object_footer: object_footer,
			description_notes: description_notes,
			footer_offset: footer_offset,
		}
	}

	/// sets the number of segments of the appropriate zff container.
	pub fn set_number_of_segments(&mut self, number: u64) {
		self.number_of_segments = number
	}

	/// returns the number of segments of the appropriate zff container.
	pub fn number_of_segments(&self) -> u64 {
		self.number_of_segments
	}

	/// adds a new <object header, segment number> combination to the inner object-header hashmap.
	pub fn add_object_header(&mut self, object_number: u64, segment_no: u64) {
		self.object_header.insert(object_number, segment_no);
	}

	/// returns the inner hashmap of object-header.
	pub fn object_header(&self) -> &HashMap<u64, u64> {
		&self.object_header
	}

	/// adds a new <object footer, segment number> combination to the inner object-footer hashmap.
	pub fn add_object_footer(&mut self, object_number: u64, segment_no: u64) {
		self.object_footer.insert(object_number, segment_no);
	}

	/// returns the inner hashmap of object-footer.
	pub fn object_footer(&self) -> &HashMap<u64, u64> {
		&self.object_footer
	}

	/// sets the start offset of this main footer.
	pub fn set_footer_offset(&mut self, offset: u64) {
		self.footer_offset = offset
	}

	/// returns the start offset of this main footer.
	pub fn footer_offset(&self) -> u64 {
		self.footer_offset
	}

	/// returns the description notes of the zff container (Not to be mixed up with the "notes" which can be created in the description header of each object!)).
	pub fn description_notes(&self) -> Option<&str> {
		Some(&self.description_notes.as_ref()?)
	}
}

impl HeaderCoding for MainFooter {
	type Item = MainFooter;

	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_MAIN_FOOTER
	}

	fn version(&self) -> u8 {
		self.version
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.version.encode_directly());
		vec.append(&mut self.number_of_segments.encode_directly());
		vec.append(&mut self.object_header.encode_directly());
		vec.append(&mut self.object_footer.encode_directly());
		if let Some(description_notes) = &self.description_notes {
			vec.append(&mut description_notes.encode_for_key(ENCODING_KEY_DESCRIPTION_NOTES));
		};
		vec.append(&mut self.footer_offset.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<MainFooter> {
		let mut cursor = Cursor::new(data);

		let footer_version = u8::decode_directly(&mut cursor)?;
		let number_of_segments = u64::decode_directly(&mut cursor)?;
		let object_header = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		let object_footer = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		let position = cursor.position();
		let description_notes = match String::decode_for_key(&mut cursor, ENCODING_KEY_DESCRIPTION_NOTES) {
			Ok(value) => Some(value),
			Err(e) => match e.get_kind() {
				ZffErrorKind::HeaderDecoderKeyNotOnPosition => {
					cursor.set_position(position);
					None
				},
				_ => return Err(e)
			},
		};
		let footer_offset = u64::decode_directly(&mut cursor)?;
		Ok(MainFooter::new(footer_version, number_of_segments, object_header, object_footer, description_notes, footer_offset))
	}
}