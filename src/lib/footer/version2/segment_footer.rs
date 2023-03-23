// - STD
use std::collections::{HashMap, BTreeMap};
use std::io::{Cursor, Read, Seek, SeekFrom};

// - internal
use crate::{
	Result,
	ZffError,
	ZffErrorKind,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER,
	DEFAULT_LENGTH_HEADER_IDENTIFIER,
	DEFAULT_LENGTH_VALUE_HEADER_LENGTH,
	ERROR_HEADER_DECODER_HEADER_LENGTH,
};

use crate::{
	FOOTER_IDENTIFIER_SEGMENT_FOOTER,
};

// - external
use byteorder::{ReadBytesExt, LittleEndian, BigEndian};


/// A wrapper for the SegmentFooter (especially for thr Segment struct)
#[derive(Debug,Clone)]
pub(crate) enum SegmentFooterWrapper {
	Footer(SegmentFooter),
	ShrinkedFooter(ShrinkedSegmentFooter)
}

impl SegmentFooterWrapper {
	pub fn new_empty_footer(version: u8) -> SegmentFooterWrapper {
		let segmentfooter = SegmentFooter::new_empty(version);
		SegmentFooterWrapper::Footer(segmentfooter)
	}

	/// creates a new SegmentFooterWrapper::Footer.
	pub fn new_footer(version: u8, 
		length_of_segment: u64, 
		object_header_offsets: HashMap<u64, u64>, 
		object_footer_offsets: HashMap<u64, u64>, 
		chunk_offsets: HashMap<u64, u64>, 
		footer_offset: u64) -> SegmentFooterWrapper {
		let segmentfooter = SegmentFooter::new(
			version, 
			length_of_segment, 
			object_header_offsets, 
			object_footer_offsets, 
			chunk_offsets, 
			footer_offset);
		SegmentFooterWrapper::Footer(segmentfooter)
	}

	/// creates a new ShrinkedSegmentFooter.
	pub fn new_shrinked_footer(
		version: u8, 
		length_of_segment: u64, 
		object_header_offsets: HashMap<u64, u64>, 
		object_footer_offsets: HashMap<u64, u64>,
		first_chunk_number: u64,
		last_chunk_number: u64,
		footer_offset: u64
		) -> SegmentFooterWrapper {
		let segmentfooter = ShrinkedSegmentFooter::new(
			version, 
			length_of_segment,
			object_header_offsets,
			object_footer_offsets,
			first_chunk_number,
			last_chunk_number,
			footer_offset);
		SegmentFooterWrapper::ShrinkedFooter(segmentfooter)
	}

	/// returns the footer version.
	pub fn version(&self) -> u8 {
		match self {
			Self::Footer(footer) => footer.version(),
			Self::ShrinkedFooter(footer) => footer.version(),
		}
	}

	/// returns the length of the segment in bytes.
	pub fn length_of_segment(&self) -> u64 {
		match self {
			Self::Footer(footer) => footer.length_of_segment(),
			Self::ShrinkedFooter(footer) => footer.length_of_segment(),
		}
	}

	/// overwrites the length value in the footer with the given value. This can be useful, if you create an 'empty'
	/// footer (with length=0) and want to set the length value after reading the data from source to buffer.
	pub fn set_length_of_segment(&mut self, value: u64) {
		match self {
			Self::Footer(footer) => footer.set_length_of_segment(value),
			Self::ShrinkedFooter(footer) => footer.set_length_of_segment(value),
		}
	}
}

/// The ShrinkedSegmentFooter is a SegmentFooter without a chunk offset table.
#[derive(Debug,Clone)]
pub(crate) struct ShrinkedSegmentFooter {
	version: u8,
	length_of_segment: u64,
	object_header_offsets: HashMap<u64, u64>, //<object number, offset>,
	object_footer_offsets: HashMap<u64, u64>, //<object number, offset>,
	first_chunk_number: u64,
	last_chunk_number: u64,
	footer_offset: u64,
}

impl ShrinkedSegmentFooter {

	/// returns the footer version.
	pub fn version(&self) -> u8 {
		self.version
	}

	/// returns the length of the segment in bytes.
	pub fn length_of_segment(&self) -> u64 {
		self.length_of_segment
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


	/// creates a new ShrinkedSegmentFooter.
	pub fn new(
		version: u8, 
		length_of_segment: u64, 
		object_header_offsets: HashMap<u64, u64>, 
		object_footer_offsets: HashMap<u64, u64>,
		first_chunk_number: u64,
		last_chunk_number: u64,
		footer_offset: u64
		) -> ShrinkedSegmentFooter {
		Self {
			version,
			length_of_segment,
			object_header_offsets,
			object_footer_offsets,
			first_chunk_number,
			last_chunk_number,
			footer_offset,
		}
	}

	/// decodes the header directly.
	pub fn decode_directly<R: Read>(data: &mut R) -> Result<ShrinkedSegmentFooter> {
		if !Self::check_identifier(data) {
			return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER));
		}
		let header_length = Self::decode_header_length(data)? as usize;
		let mut header_content = vec![0u8; header_length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
		data.read_exact(&mut header_content)?;
		Self::decode_content(header_content)
	}

	/// decodes the content of the header.
	fn decode_content(data: Vec<u8>) -> Result<ShrinkedSegmentFooter> {
		let mut cursor = Cursor::new(data);

		let footer_version = u8::decode_directly(&mut cursor)?;
		let length_of_segment = u64::decode_directly(&mut cursor)?;
		let object_header_offsets = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		let object_footer_offsets = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		let length = u64::decode_directly(&mut cursor)? as i64;
		let first_chunk_number = u64::decode_directly(&mut cursor)?;
		cursor.seek(SeekFrom::Current(8))?; // u64
		cursor.seek(SeekFrom::Current((length-2)*8*2))?; //length of HashMap * size_of(u64) * 2
		let last_chunk_number = u64::decode_directly(&mut cursor)?;
		cursor.seek(SeekFrom::Current(8))?; // u64
		let footer_offset = u64::decode_directly(&mut cursor)?;
		Ok(ShrinkedSegmentFooter::new(
			footer_version, 
			length_of_segment, 
			object_header_offsets,
			object_footer_offsets,
			first_chunk_number,
			last_chunk_number, 
			footer_offset))
	}

	/// decodes the length of the header.
	fn decode_header_length<R: Read>(data: &mut R) -> Result<u64> {
		match data.read_u64::<LittleEndian>() {
			Ok(value) => Ok(value),
			Err(_) => Err(ZffError::new_header_decode_error(ERROR_HEADER_DECODER_HEADER_LENGTH)),
		}
	}

	/// checks if the read identifier is valid for this header.
	fn check_identifier<R: Read>(data: &mut R) -> bool {
		let identifier = match data.read_u32::<BigEndian>() {
			Ok(val) => val,
			Err(_) => return false,
		};
		identifier == Self::identifier()
	}

	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_SEGMENT_FOOTER
	}
}

/// The SegmentFooter is a footer which is be written at the end of each segment.
/// The footer contains a table on the chunks, present in the appropriate segment.
/// The offset table is internally managed as a ```HashMap<u64, u64>```.
#[derive(Debug,Clone)]
pub struct SegmentFooter {
	version: u8,
	length_of_segment: u64,
	object_header_offsets: HashMap<u64, u64>, //<object number, offset>,
	object_footer_offsets: HashMap<u64, u64>, //<object number, offset>,
	chunk_offsets: HashMap<u64, u64>, //<chunk number, offset>
	/// The offset where the footer starts.
	footer_offset: u64,

}

impl SegmentFooter {
	/// creates a new empty SegmentFooter.
	pub fn new_empty(version: u8) -> SegmentFooter {
		Self {
			version,
			length_of_segment: 0,
			object_header_offsets: HashMap::new(),
			object_footer_offsets: HashMap::new(),
			chunk_offsets: HashMap::new(),
			footer_offset: 0,
		}
	}

	/// creates a new SegmentFooter.
	pub fn new(version: u8, length_of_segment: u64, object_header_offsets: HashMap<u64, u64>, object_footer_offsets: HashMap<u64, u64>, chunk_offsets: HashMap<u64, u64>, footer_offset: u64) -> SegmentFooter {
		Self {
			version,
			length_of_segment,
			object_header_offsets,
			object_footer_offsets,
			chunk_offsets,
			footer_offset,
		}
	}

	/// returns the length of the segment in bytes.
	pub fn length_of_segment(&self) -> u64 {
		self.length_of_segment
	}

	/// overwrites the length value in the footer with the given value. This can be useful, if you create an 'empty'
	/// footer (with length=0) and want to set the length value after reading the data from source to buffer.
	pub fn set_length_of_segment(&mut self, value: u64) {
		self.length_of_segment = value
	}

	/// adds an offset to the chunk offset table of the SegmentFooter.
	pub fn add_chunk_offset(&mut self, chunk_number: u64, offset: u64) {
		self.chunk_offsets.insert(chunk_number, offset);
	}

	/// returns a reference of the chunk offset table
	pub fn chunk_offsets(&self) -> &HashMap<u64, u64> {
		&self.chunk_offsets
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
		vec.append(&mut self.chunk_offsets.encode_directly());
		vec.append(&mut self.footer_offset.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<SegmentFooter> {
		let mut cursor = Cursor::new(data);

		let footer_version = u8::decode_directly(&mut cursor)?;
		let length_of_segment = u64::decode_directly(&mut cursor)?;
		let object_header_offsets = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		let object_footer_offsets = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		let chunk_offsets = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		let footer_offset = u64::decode_directly(&mut cursor)?;
		Ok(SegmentFooter::new(footer_version, length_of_segment, object_header_offsets, object_footer_offsets, chunk_offsets, footer_offset))
	}
}

/// This is a variant of the [SegmentFooter] which uses [BTreeMap](std::collections::BTreeMap)s instead of HashMaps.
/// There could be cases in which this variant **may** be faster that a normal [SegmentFooter] as some maps have to be stored sorted by their keys.
#[derive(Debug,Clone)]
pub struct SegmentFooterBTree {
    version: u8,
    length_of_segment: u64,
    object_header_offsets: BTreeMap<u64, u64>, //<object number, offset>,
    object_footer_offsets: BTreeMap<u64, u64>, //<object number, offset>,
    chunk_offsets: BTreeMap<u64, u64>, //<chunk number, offset>
    /// The offset where the footer starts.
    footer_offset: u64,

}

impl SegmentFooterBTree {
    /// creates a new empty SegmentFooterBTree.
    pub fn new_empty(version: u8) -> SegmentFooterBTree {
        Self {
            version,
            length_of_segment: 0,
            object_header_offsets: BTreeMap::new(),
            object_footer_offsets: BTreeMap::new(),
            chunk_offsets: BTreeMap::new(),
            footer_offset: 0,
        }
    }

    /// creates a new SegmentFooterBTree.
    pub fn new(version: u8, length_of_segment: u64, object_header_offsets: BTreeMap<u64, u64>, object_footer_offsets: BTreeMap<u64, u64>, chunk_offsets: BTreeMap<u64, u64>, footer_offset: u64) -> SegmentFooterBTree {
        Self {
            version,
            length_of_segment,
            object_header_offsets,
            object_footer_offsets,
            chunk_offsets,
            footer_offset,
        }
    }
    
    /// returns the length of the segment in bytes.
    pub fn length_of_segment(&self) -> u64 {
        self.length_of_segment
    }

    /// overwrites the length value in the footer with the given value. This can be useful, if you create an 'empty'
    /// footer (with length=0) and want to set the length value after reading the data from source to buffer.
    pub fn set_length_of_segment(&mut self, value: u64) {
        self.length_of_segment = value
    }

    /// adds an offset to the chunk offset table of the SegmentFooterBTree.
    pub fn add_chunk_offset(&mut self, chunk_number: u64, offset: u64) {
        self.chunk_offsets.insert(chunk_number, offset);
    }

    /// returns a reference of the chunk offset table
    pub fn chunk_offsets(&self) -> &BTreeMap<u64, u64> {
        &self.chunk_offsets
    }

    /// adds an offset to the object header offset table of the SegmentFooterBTree.
    pub fn add_object_header_offset(&mut self, object_number: u64, offset: u64) {
        self.object_header_offsets.insert(object_number, offset);
    }

    /// returns a reference of the object header offset table
    pub fn object_header_offsets(&self) -> &BTreeMap<u64, u64> {
        &self.object_header_offsets
    }

    /// adds an offset to the object footer offset table of the SegmentFooterBTree.
    pub fn add_object_footer_offset(&mut self, object_number: u64, offset: u64) {
        self.object_footer_offsets.insert(object_number, offset);
    }

    /// returns a reference of the object footer offset table
    pub fn object_footer_offsets(&self) -> &BTreeMap<u64, u64> {
        &self.object_footer_offsets
    }
   /// sets the offset of this footer
    pub fn set_footer_offset(&mut self, offset: u64) {
        self.footer_offset = offset;
    }
}

impl HeaderCoding for SegmentFooterBTree {
    type Item = SegmentFooterBTree;

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
        vec.append(&mut self.chunk_offsets.encode_directly());
        vec.append(&mut self.footer_offset.encode_directly());
        vec
    }

    fn decode_content(data: Vec<u8>) -> Result<SegmentFooterBTree> {
        let mut cursor = Cursor::new(data);

        let footer_version = u8::decode_directly(&mut cursor)?;
        let length_of_segment = u64::decode_directly(&mut cursor)?;
        let object_header_offsets = BTreeMap::<u64, u64>::decode_directly(&mut cursor)?;
        let object_footer_offsets = BTreeMap::<u64, u64>::decode_directly(&mut cursor)?;
        let chunk_offsets = BTreeMap::<u64, u64>::decode_directly(&mut cursor)?;
        let footer_offset = u64::decode_directly(&mut cursor)?;
        Ok(SegmentFooterBTree::new(footer_version, length_of_segment, object_header_offsets, object_footer_offsets, chunk_offsets, footer_offset))
    }
}
