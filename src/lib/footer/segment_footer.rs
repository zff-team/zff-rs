// - STD
use std::collections::{HashMap, BTreeMap};
use std::io::{Cursor};

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	DEFAULT_FOOTER_VERSION_SEGMENT_FOOTER,
};

use crate::{
	FOOTER_IDENTIFIER_SEGMENT_FOOTER,
};

// - external


/// The SegmentFooter is a footer which is be written at the end of each segment.
/// The footer contains a table on the chunks, present in the appropriate segment.
/// The offset table is internally managed as a ```HashMap<u64, u64>```.
#[derive(Debug,Clone)]
pub struct SegmentFooter {
	pub version: u8,
	pub length_of_segment: u64,
	pub object_header_offsets: HashMap<u64, u64>, //<object number, offset>,
	pub object_footer_offsets: HashMap<u64, u64>, //<object number, offset>,
	pub chunk_map_table: BTreeMap<u64, u64>, //<highest chunk number, offset>
	pub first_chunk_number: u64,
	/// The offset where the footer starts.
	pub footer_offset: u64,

}

impl Default for SegmentFooter {
	fn default() -> Self {
		SegmentFooter::new_empty(DEFAULT_FOOTER_VERSION_SEGMENT_FOOTER)
	}
}

impl SegmentFooter {
	/// creates a new empty SegmentFooter.
	pub fn new_empty(version: u8) -> SegmentFooter {
		Self {
			version,
			length_of_segment: 0,
			object_header_offsets: HashMap::new(),
			object_footer_offsets: HashMap::new(),
			chunk_map_table: BTreeMap::new(),
			first_chunk_number: 0,
			footer_offset: 0,
		}
	}

	/// creates a new SegmentFooter.
	pub fn new(
		version: u8, 
		length_of_segment: u64, 
		object_header_offsets: HashMap<u64, u64>, 
		object_footer_offsets: HashMap<u64, u64>, 
		chunk_map_table: BTreeMap<u64, u64>,
		first_chunk_number: u64,
		footer_offset: u64) -> SegmentFooter {
		Self {
			version,
			length_of_segment,
			object_header_offsets,
			object_footer_offsets,
			chunk_map_table,
			first_chunk_number,
			footer_offset,
		}
	}

	/// overwrites the length value in the footer with the given value. This can be useful, if you create an 'empty'
	/// footer (with length=0) and want to set the length value after reading the data from source to buffer.
	pub fn set_length_of_segment(&mut self, value: u64) {
		self.length_of_segment = value
	}

	/// adds an offset to the object header offset table of the SegmentFooter.
	pub fn add_object_header_offset(&mut self, object_number: u64, offset: u64) {
		self.object_header_offsets.insert(object_number, offset);
	}

	/// returns a reference of the object header offset table
	pub fn object_header_offsets(&self) -> &HashMap<u64, u64> {
		&self.object_header_offsets
	}

	/// adds an offset to the object footer offset table of the SegmentFooter.
	pub fn add_object_footer_offset(&mut self, object_number: u64, offset: u64) {
		self.object_footer_offsets.insert(object_number, offset);
	}

	/// returns a reference of the object footer offset table
	pub fn object_footer_offsets(&self) -> &HashMap<u64, u64> {
		&self.object_footer_offsets
	}

	/// sets the offset of this footer
	pub fn set_footer_offset(&mut self, offset: u64) {
		self.footer_offset = offset;
	}
}

impl HeaderCoding for SegmentFooter {
	type Item = SegmentFooter;

	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_SEGMENT_FOOTER
	}

	fn version(&self) -> u8 {
		self.version
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.version.encode_directly());
		vec.append(&mut self.length_of_segment.encode_directly());
		vec.append(&mut self.object_header_offsets.encode_directly());
		vec.append(&mut self.object_footer_offsets.encode_directly());
		vec.append(&mut self.chunk_map_table.encode_directly());
		vec.append(&mut self.first_chunk_number.encode_directly());
		vec.append(&mut self.footer_offset.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<SegmentFooter> {
		let mut cursor = Cursor::new(data);

		let footer_version = u8::decode_directly(&mut cursor)?;
		let length_of_segment = u64::decode_directly(&mut cursor)?;
		let object_header_offsets = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		let object_footer_offsets = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		let chunk_map_table = BTreeMap::<u64, u64>::decode_directly(&mut cursor)?;
		let first_chunk_number = u64::decode_directly(&mut cursor)?;
		let footer_offset = u64::decode_directly(&mut cursor)?;
		Ok(SegmentFooter::new(footer_version, length_of_segment, object_header_offsets, object_footer_offsets, chunk_map_table, first_chunk_number, footer_offset))
	}
}