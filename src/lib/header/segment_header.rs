// - STD
use std::cmp::{PartialEq};
use std::io::{Cursor};

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	HEADER_IDENTIFIER_SEGMENT_HEADER,
};

/// The [SegmentHeader] contains a lot of initial metadata of the appropriate segment. Each segment has its own segment header.\
/// The following metadata are included in the [SegmentHeader]:
/// - The unique identifier value
/// - the number of the appropriate segment (the first segment starts always with a 1).
#[derive(Debug,Clone,Eq)]
pub struct SegmentHeader {
	version: u8,
	unique_identifier: u64,
	segment_number: u64,
	chunkmap_size: u64,
}

impl SegmentHeader {
	/// returns a new [SegmentHeader] with the given values.
	pub fn new(version: u8, unique_identifier: u64, segment_number: u64, chunkmap_size: u64) -> SegmentHeader {
		Self {
			version,
			unique_identifier,
			segment_number,
			chunkmap_size,
		}
	}

	/// returns the unique identifier of the zff container (each segment should have the same identifier).
	pub fn unique_identifier(&self) -> u64 {
		self.unique_identifier
	}

	/// returns the number of this segment.
	pub fn segment_number(&self) -> u64 {
		self.segment_number
	}

	/// sets the segment number to the next number. This can be useful, for example,
	/// if you clone a segment header from the previous one or something like that.
	pub fn next_header(&self) -> SegmentHeader {
		SegmentHeader {
			version: self.version,
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

	fn version(&self) -> u8 {
		self.version
	}
	
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.append(&mut self.version.encode_directly());
		vec.append(&mut self.unique_identifier.encode_directly());
		vec.append(&mut self.segment_number.encode_directly());
		vec.append(&mut self.chunkmap_size.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<SegmentHeader> {
		let mut cursor = Cursor::new(data);

		let version = u8::decode_directly(&mut cursor)?;
		let unique_identifier = u64::decode_directly(&mut cursor)?;
		let segment_number = u64::decode_directly(&mut cursor)?;
		let chunkmap_size = u64::decode_directly(&mut cursor)?;
		Ok(SegmentHeader::new(version, unique_identifier, segment_number, chunkmap_size))
	}
}

impl PartialEq for SegmentHeader {
    fn eq(&self, other: &Self) -> bool {
        self.segment_number == other.segment_number
    }
}