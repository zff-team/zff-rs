// - STD
use std::cmp::{PartialEq};
use std::borrow::Borrow;
use std::io::{Cursor,Read,Seek,SeekFrom};
use std::collections::HashMap;

// - internal
use crate::{
	Result,
	HeaderObject,
	HeaderEncoder,
	HeaderDecoder,
	header::{ChunkHeader},
	ValueEncoder,
	ValueDecoder,
	ZffError,
	ZffErrorKind,
	CompressionAlgorithm,
	HEADER_IDENTIFIER_SEGMENT_HEADER,
	HEADER_IDENTIFIER_SEGMENT_FOOTER,
	CHUNK_HEADER_CONTENT_LEN_WITH_SIGNATURE,
	CHUNK_HEADER_CONTENT_LEN_WITHOUT_SIGNATURE,
};

// - external
use serde::{Serialize};
use slice::IoSlice;
use zstd;

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
	/// returns a new empty segment header
	pub fn new_empty(header_version: u8, unique_identifier: i64, segment_number: u64) -> SegmentHeader {
		Self {
			header_version: header_version,
			unique_identifier: unique_identifier,
			segment_number: segment_number,
			length_of_segment: 0,
			footer_offset: 0,
		}
	}
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
		vec.append(&mut self.footer_offset.encode_directly());

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

impl<R: 'static +  Read + Seek> Segment<R> {
	fn new(header: SegmentHeader, data: R, chunk_offsets: HashMap<u64, u64>) -> Segment<R> {
		Self {
			header: header,
			data: data,
			chunk_offsets: chunk_offsets,
		}
	}

	pub fn new_from_reader(mut data: R) -> Result<Segment<R>> {
		let stream_position = data.stream_position()?; //uses the current stream position. This is important for the first segment (which contains a main header);
		let segment_header = SegmentHeader::decode_directly(&mut data)?;
		let footer_offset = segment_header.footer_offset();
		let initial_chunk_header = ChunkHeader::decode_directly(&mut data)?;
		let initial_chunk_number = initial_chunk_header.chunk_number();
		data.seek(SeekFrom::Start(footer_offset))?;
		let segment_footer = SegmentFooter::decode_directly(&mut data)?;
		let mut chunk_offsets = HashMap::new();
		let mut chunk_number = initial_chunk_number;
		for offset in segment_footer.chunk_offsets() {
			chunk_offsets.insert(chunk_number, *offset);
			chunk_number += 1;
		}
		data.seek(SeekFrom::Start(stream_position))?;
		let _ = SegmentHeader::decode_directly(&mut data)?;
		Ok(Self::new(segment_header, data, chunk_offsets))
	}

	pub fn chunk_data<C>(&mut self, chunk_number: u64, compression_algorithm: C) -> Result<Vec<u8>>
	where
		C: Borrow<CompressionAlgorithm>,
	{
		let chunk_offset = match self.chunk_offsets.get(&chunk_number) {
			Some(offset) => offset,
			None => return Err(ZffError::new(ZffErrorKind::DataDecodeChunkNumberNotInSegment, chunk_number.to_string()))
		};
		self.data.seek(SeekFrom::Start(*chunk_offset))?;
		let chunk_header = ChunkHeader::decode_directly(&mut self.data)?;
		let chunk_size = chunk_header.chunk_size();
		let chunk_header_size = if chunk_header.signature().is_some() {
			CHUNK_HEADER_CONTENT_LEN_WITH_SIGNATURE
		} else {
			CHUNK_HEADER_CONTENT_LEN_WITHOUT_SIGNATURE
		};
		let bytes_to_skip = chunk_header_size as u64 + *chunk_offset;
		let mut chunk_data = IoSlice::new(self.data.by_ref(), bytes_to_skip, *chunk_size)?;
		let mut buffer = Vec::new();
		match compression_algorithm.borrow() {
			CompressionAlgorithm::None => {
				chunk_data.read_to_end(&mut buffer)?;
				return Ok(buffer);
			}
			CompressionAlgorithm::Zstd => {
				let mut decoder = zstd::stream::read::Decoder::new(chunk_data)?;
				decoder.read_to_end(&mut buffer)?;
				return Ok(buffer);
			}
		}
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