// - STD
use std::io::{Cursor, Read};
use std::collections::HashMap;

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueDecoder,
	ValueEncoder,
	ZffError,
	ZffErrorKind,
	FOOTER_IDENTIFIER_OBJECT_FOOTER_PHYSICAL,
	FOOTER_IDENTIFIER_OBJECT_FOOTER_LOGICAL,
	DEFAULT_LENGTH_VALUE_HEADER_LENGTH,
	DEFAULT_LENGTH_HEADER_IDENTIFIER,
	ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER,
	ERROR_HEADER_DECODER_HEADER_LENGTH,
};
use crate::version2::header::{
	HashHeader,
};

// - external
use byteorder::{LittleEndian, BigEndian, ReadBytesExt};


#[derive(Debug, Clone)]
pub enum ObjectFooter {
	Physical(ObjectFooterPhysical),
	Logical(ObjectFooterLogical),
}

impl ObjectFooter {

	pub fn version(&self) -> u8 {
		match self {
			ObjectFooter::Physical(phy) => phy.version(),
			ObjectFooter::Logical(log) => log.version(),
		}
	}

	/// checks if the identifier matches to an physical or logical object footer. Returns 1 for a physical object footer, 2 for a logical object footer and 0 if neither applies.
	fn check_identifier<R: Read>(data: &mut R) -> u8 {
		let identifier = match data.read_u32::<BigEndian>() {
			Ok(val) => val,
			Err(_) => return 0,
		};
		if identifier == ObjectFooterPhysical::identifier() { 
			return 1;
		} else if identifier == ObjectFooterLogical::identifier() {
			return 2;
		} else {
			return 0;
		}
	}

	/// decodes the length of the header.
	fn decode_header_length<R: Read>(data: &mut R) -> Result<u64> {
		match data.read_u64::<LittleEndian>() {
			Ok(value) => Ok(value),
			Err(_) => Err(ZffError::new_header_decode_error(ERROR_HEADER_DECODER_HEADER_LENGTH)),
		}
	}

	/// decodes the header directly.
	pub fn decode_directly<R: Read>(data: &mut R) -> Result<ObjectFooter> {
		match Self::check_identifier(data) {
			1 => {
				let length = Self::decode_header_length(data)? as usize;
				let mut content_buffer = vec![0u8; length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
				data.read_exact(&mut content_buffer)?;
				return Ok(ObjectFooter::Physical(ObjectFooterPhysical::decode_content(content_buffer)?));
			},
			2 => {
				let length = Self::decode_header_length(data)? as usize;
				let mut content_buffer = vec![0u8; length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
				data.read_exact(&mut content_buffer)?;
				return Ok(ObjectFooter::Logical(ObjectFooterLogical::decode_content(content_buffer)?));
			},
			_ => return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER)),
		}
	}
}

#[derive(Debug,Clone)]
pub struct ObjectFooterPhysical {
	version: u8,
	acquisition_start: u64,
	acquisition_end: u64,
	length_of_data: u64,
	first_chunk_number: u64,
	number_of_chunks: u64,
	hash_header: HashHeader,
}

impl ObjectFooterPhysical {
	pub fn new(version: u8, acquisition_start: u64, acquisition_end: u64, length_of_data: u64, first_chunk_number: u64, number_of_chunks: u64, hash_header: HashHeader) -> ObjectFooterPhysical {
		Self {
			version: version,
			acquisition_start: acquisition_start,
			acquisition_end: acquisition_end,
			length_of_data: length_of_data,
			first_chunk_number: first_chunk_number,
			number_of_chunks: number_of_chunks,
			hash_header: hash_header,
		}
	}

	pub fn acquisition_start(&self) -> u64 {
		self.acquisition_start
	}

	pub fn acquisition_end(&self) -> u64 {
		self.acquisition_end
	}

	pub fn first_chunk_number(&self) -> u64 {
		self.first_chunk_number
	}

	pub fn number_of_chunks(&self) -> u64 {
		self.number_of_chunks
	}

	pub fn length_of_data(&self) -> u64 {
		self.length_of_data
	}

	pub fn hash_header(&self) -> &HashHeader {
		&self.hash_header
	}
}

impl HeaderCoding for ObjectFooterPhysical {
	type Item = ObjectFooterPhysical;
	fn version(&self) -> u8 { 
		self.version
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_OBJECT_FOOTER_PHYSICAL
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(self.version);
		vec.append(&mut self.acquisition_start.encode_directly());
		vec.append(&mut self.acquisition_end.encode_directly());
		vec.append(&mut self.length_of_data.encode_directly());
		vec.append(&mut self.first_chunk_number.encode_directly());
		vec.append(&mut self.number_of_chunks.encode_directly());
		vec.append(&mut self.hash_header.encode_directly());
		vec
	}
	fn decode_content(data: Vec<u8>) -> Result<ObjectFooterPhysical> {
		let mut cursor = Cursor::new(data);
		let footer_version = u8::decode_directly(&mut cursor)?;
		let acquisition_start = u64::decode_directly(&mut cursor)?;
		let acquisition_end = u64::decode_directly(&mut cursor)?;
		let length_of_data = u64::decode_directly(&mut cursor)?;
		let first_chunk_number = u64::decode_directly(&mut cursor)?;
		let number_of_chunks = u64::decode_directly(&mut cursor)?;
		let hash_header = HashHeader::decode_directly(&mut cursor)?;
		Ok(ObjectFooterPhysical::new(footer_version, acquisition_start, acquisition_end, length_of_data, first_chunk_number, number_of_chunks, hash_header))
	}
}

#[derive(Debug,Clone)]
pub struct ObjectFooterLogical {
	version: u8,
	file_header_segment_numbers: HashMap<u64, u64>,
	file_header_offsets: HashMap<u64, u64>,
	file_footer_segment_numbers: HashMap<u64, u64>,
	file_footer_offsets: HashMap<u64, u64>,
}

impl ObjectFooterLogical {
	pub fn new_empty(version: u8) -> ObjectFooterLogical {
		Self {
			version: version,
			file_header_segment_numbers: HashMap::new(),
			file_header_offsets: HashMap::new(),
			file_footer_segment_numbers: HashMap::new(),
			file_footer_offsets: HashMap::new()
		}
	}
	pub fn new(
		version: u8,
		file_header_segment_numbers: HashMap<u64, u64>,
		file_header_offsets: HashMap<u64, u64>,
		file_footer_segment_numbers: HashMap<u64, u64>,
		file_footer_offsets: HashMap<u64, u64>) -> ObjectFooterLogical {
		Self {
			version: version,
			file_header_segment_numbers: file_header_segment_numbers,
			file_header_offsets: file_header_offsets,
			file_footer_segment_numbers: file_footer_segment_numbers,
			file_footer_offsets: file_footer_offsets,
		}
	}

	pub fn add_file_header_segment_number(&mut self, filenumber: u64, file_segment_number: u64) {
		self.file_header_segment_numbers.insert(filenumber, file_segment_number);
	}

	pub fn add_file_header_offset(&mut self, filenumber: u64, fileoffset: u64) {
		self.file_header_offsets.insert(filenumber, fileoffset);
	}

	pub fn file_header_segment_numbers(&self) -> &HashMap<u64, u64> {
		&self.file_header_segment_numbers
	}

	pub fn file_header_offsets(&self) -> &HashMap<u64, u64> {
		&self.file_header_offsets
	}

	pub fn add_file_footer_segment_number(&mut self, filenumber: u64, file_segment_number: u64) {
		self.file_footer_segment_numbers.insert(filenumber, file_segment_number);
	}

	pub fn add_file_footer_offset(&mut self, filenumber: u64, fileoffset: u64) {
		self.file_footer_offsets.insert(filenumber, fileoffset);
	}

	pub fn file_footer_segment_numbers(&self) -> &HashMap<u64, u64> {
		&self.file_footer_segment_numbers
	}

	pub fn file_footer_offsets(&self) -> &HashMap<u64, u64> {
		&self.file_footer_offsets
	}
}

impl HeaderCoding for ObjectFooterLogical {
	type Item = ObjectFooterLogical;

	fn version(&self) -> u8 { 
		self.version
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_OBJECT_FOOTER_LOGICAL
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(self.version);
		vec.append(&mut self.file_footer_segment_numbers.encode_directly());
		vec.append(&mut self.file_footer_offsets.encode_directly());
		vec
	}
	fn decode_content(data: Vec<u8>) -> Result<ObjectFooterLogical> {
		let mut cursor = Cursor::new(data);
		let footer_version = u8::decode_directly(&mut cursor)?;
		let file_header_segment_numbers = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		let file_header_offsets = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		let file_footer_segment_numbers = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		let file_footer_offsets = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		Ok(ObjectFooterLogical::new(footer_version, file_header_segment_numbers, file_header_offsets, file_footer_segment_numbers, file_footer_offsets))
	}

}