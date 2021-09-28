// - STD
use std::cmp::{PartialEq};
use std::io::{Cursor,Read,Seek,SeekFrom};
use std::collections::HashMap;

// - internal
use crate::{
	Result,
	HeaderObject,
	HeaderEncoder,
	HeaderDecoder,
	ValueEncoder,
	ValueDecoder,
	HEADER_IDENTIFIER_SEGMENT_HEADER,
	HEADER_IDENTIFIER_SEGMENT_FOOTER,
};

// - external
use serde::{Serialize};

/// The segment header contains all informations about the specific segment. Each segment has his own segment header.\
/// This header is **not** a part of the main header.\
#[derive(Debug,Clone,Eq,Serialize)]
pub struct SegmentHeader {
	header_version: u8,
	unique_identifier: i64,
	segment_number: u64,
	length_of_segment: u64,
	footer_offset: u64,
}

impl SegmentHeader {
	/// returns a new segment header with the given values.
	pub fn new(header_version: u8, unique_identifier: i64, segment_number: u64, length_of_segment: u64, footer_offset: u64) -> SegmentHeader {
		Self {
			header_version: header_version,
			unique_identifier: unique_identifier,
			segment_number: segment_number,
			length_of_segment: length_of_segment,
			footer_offset: footer_offset,
		}
	}

	/// returns the version of the segment header.
	pub fn header_version(&self) -> u8 {
		self.header_version
	}

	/// returns the unique identifier of image (each segment should have the same identifier).
	pub fn unique_identifier(&self) -> i64 {
		self.unique_identifier
	}

	/// returns the segment number.
	pub fn segment_number(&self) -> u64 {
		self.segment_number
	}

	/// returns the length of the segment in bytes.
	pub fn length_of_segment(&self) -> u64 {
		self.length_of_segment
	}

	/// overwrites the length value in the header with the given value. This can be useful, if you create an 'empty'
	/// header (with length=0) and want to set the length value after reading the data from source to buffer.
	pub fn set_length_of_segment(&mut self, value: u64) {
		self.length_of_segment = value
	}

	/// sets the segment number to the next number. This can be useful, for example,
	/// if you clone a segment header from the previous one or something like that.
	pub fn next_header(&self) -> SegmentHeader {
		SegmentHeader {
			header_version: self.header_version,
			unique_identifier: self.unique_identifier,
			segment_number: self.segment_number+1,
			length_of_segment: 0,
			footer_offset: 0,
		}
	}

	/// sets the offset of the segment footer.
	pub fn set_footer_offset(&mut self, offset: u64) {
		self.footer_offset = offset
	}

	/// returns the footer offset.
	pub fn footer_offset(&self) -> u64 {
		self.footer_offset
	}
}

impl HeaderObject for SegmentHeader {
	fn identifier() -> u32 {
		HEADER_IDENTIFIER_SEGMENT_HEADER
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.append(&mut self.header_version.encode_directly());
		vec.append(&mut self.unique_identifier.encode_directly());
		vec.append(&mut self.segment_number.encode_directly());
		vec.append(&mut self.length_of_segment.encode_directly());

		vec
	}
}

impl HeaderEncoder for SegmentHeader {}

impl HeaderDecoder for SegmentHeader {
	type Item = SegmentHeader;

	fn decode_content(data: Vec<u8>) -> Result<SegmentHeader> {
		let mut cursor = Cursor::new(data);

		let header_version = u8::decode_directly(&mut cursor)?;
		let unique_identifier = i64::decode_directly(&mut cursor)?;
		let segment_number = u64::decode_directly(&mut cursor)?;
		let length = u64::decode_directly(&mut cursor)?;
		let footer_offset = u64::decode_directly(&mut cursor)?;
		Ok(SegmentHeader::new(header_version, unique_identifier, segment_number, length, footer_offset))
	}
}

impl PartialEq for SegmentHeader {
    fn eq(&self, other: &Self) -> bool {
        self.segment_number == other.segment_number
    }
}

/// The SegmentFooter is a footer which is be written at the end of the segment.
/// This footer contains the offsets to the chunks.
pub struct SegmentFooter {
	version: u8,
	chunk_offsets: Vec<u64>
}

impl SegmentFooter {
	/// creates a new empty SegmentFooter.
	pub fn new_empty(version: u8) -> SegmentFooter {
		Self {
			version: version,
			chunk_offsets: Vec::new()
		}
	}

	/// creates a new SegmentFooter with given offsets.
	pub fn new(version: u8, chunk_offsets: Vec<u64>) -> SegmentFooter {
		Self {
			version: version,
			chunk_offsets: chunk_offsets,
		}
	}

	/// adds an offset to the SegmentFooter.
	pub fn add_offset(&mut self, offset: u64) {
		self.chunk_offsets.push(offset)
	}

	/// returns the saved offsets
	pub fn chunk_offsets(&self) -> &Vec<u64> {
		&self.chunk_offsets
	}
}

impl HeaderObject for SegmentFooter {
	fn identifier() -> u32 {
		HEADER_IDENTIFIER_SEGMENT_FOOTER
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.append(&mut self.version.encode_directly());
		vec.append(&mut self.chunk_offsets.encode_directly());

		vec
	}
}

impl HeaderEncoder for SegmentFooter {}

impl HeaderDecoder for SegmentFooter {
	type Item = SegmentFooter;

	fn decode_content(data: Vec<u8>) -> Result<SegmentFooter> {
		let mut cursor = Cursor::new(data);

		let footer_version = u8::decode_directly(&mut cursor)?;
		let chunk_offsets = Vec::<u64>::decode_directly(&mut cursor)?;
		Ok(SegmentFooter::new(footer_version, chunk_offsets))
	}
}

/// Segment object
pub struct Segment<R: Read + Seek> {
	header: SegmentHeader,
	data: R,
	chunk_offsets: HashMap<u64, u64> //<chunk number, offset>
}

impl<R: Read + Seek> Segment<R> {
	pub fn new(header: SegmentHeader, data: R, chunk_offsets: HashMap<u64, u64>) -> Segment<R> {
		Self {
			header: header,
			data: data,
			chunk_offsets: chunk_offsets,
		}
	}

	pub fn new_from_reader(mut data: R, initial_chunk_number: u64) -> Result<Segment<R>> {
		let segment_header = SegmentHeader::decode_directly(&mut data)?;
		
		let footer_offset = segment_header.footer_offset();
		data.seek(SeekFrom::Start(footer_offset))?;
		let segment_footer = SegmentFooter::decode_directly(&mut data)?;
		let mut chunk_offsets = HashMap::new();
		let mut chunk_number = initial_chunk_number;
		for offset in segment_footer.chunk_offsets() {
			chunk_offsets.insert(chunk_number, *offset);
			chunk_number += 1;
		}

		data.seek(SeekFrom::Start(0))?;
		let _ = SegmentHeader::decode_directly(&mut data)?;

		Ok(Self::new(segment_header, data, chunk_offsets))
	}

	pub fn header(&self) -> &SegmentHeader {
		&self.header
	}

	pub fn chunk_offsets(&self) -> &HashMap<u64, u64> {
		&self.chunk_offsets
	}

	pub fn data(&self) -> &R {
		&self.data
	}
}