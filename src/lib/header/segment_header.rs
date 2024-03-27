// - STD
use std::io::Cursor;
use std::fmt;

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	HEADER_IDENTIFIER_SEGMENT_HEADER,
	DEFAULT_HEADER_VERSION_SEGMENT_HEADER,
};

// - external
#[cfg(feature = "serde")]
use serde::{
	Deserialize,
	Serialize,
};

/// The [SegmentHeader] contains a lot of initial metadata of the appropriate segment. Each segment has its own segment header.\
/// The following metadata are included in the [SegmentHeader]:
/// - The unique identifier value
/// - the number of the appropriate segment (the first segment starts always with a 1).
/// - the target chunkmap size.
#[derive(Debug,Clone,Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct SegmentHeader {
	/// the unique identifier. Segments at the same group (=same zff container) should have the same identifier.
	#[cfg_attr(feature = "serde", serde(serialize_with = "crate::helper::as_hex"))]
	pub unique_identifier: u64,
	/// the appropriate segment number.
	pub segment_number: u64,
	/// the target size of a chunkmap.
	pub chunkmap_size: u64,
}

impl SegmentHeader {
	/// returns a new [SegmentHeader] with the given values.
	pub fn new(unique_identifier: u64, segment_number: u64, chunkmap_size: u64) -> SegmentHeader {
		Self {
			unique_identifier,
			segment_number,
			chunkmap_size,
		}
	}

	/// sets the segment number to the next number. This can be useful, for example,
	/// if you clone a segment header from the previous one or something like that.
	pub fn next_header(&self) -> SegmentHeader {
		SegmentHeader {
			unique_identifier: self.unique_identifier,
			segment_number: self.segment_number+1,
			chunkmap_size: self.chunkmap_size
		}
	}
}

impl HeaderCoding for SegmentHeader {
	type Item = SegmentHeader;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_SEGMENT_HEADER
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_SEGMENT_HEADER
	}
	
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut Self::version().encode_directly());
		vec.append(&mut self.unique_identifier.encode_directly());
		vec.append(&mut self.segment_number.encode_directly());
		vec.append(&mut self.chunkmap_size.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<SegmentHeader> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?; // check version (and skip it)
		let unique_identifier = u64::decode_directly(&mut cursor)?;
		let segment_number = u64::decode_directly(&mut cursor)?;
		let chunkmap_size = u64::decode_directly(&mut cursor)?;
		Ok(SegmentHeader::new(unique_identifier, segment_number, chunkmap_size))
	}
}

impl PartialEq for SegmentHeader {
    fn eq(&self, other: &Self) -> bool {
        self.segment_number == other.segment_number
    }
}

// - implement fmt::Display
impl fmt::Display for SegmentHeader {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl SegmentHeader {
	fn struct_name(&self) -> &'static str {
		"SegmentHeader"
	}
}