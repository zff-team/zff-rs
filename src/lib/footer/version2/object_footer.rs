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
use crate::header::{
	HashHeader,
};

// - external
use byteorder::{LittleEndian, BigEndian, ReadBytesExt};

/// Each object contains its own object footer.
#[derive(Debug, Clone)]
pub enum ObjectFooter {
	/// A physical object contains a [ObjectFooterPhysical].
	Physical(ObjectFooterPhysical),
	/// A logical object contains a [ObjectFooterLogical].
	Logical(ObjectFooterLogical),
}

impl ObjectFooter {
	/// returns the version of the object footer.
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
			1
		} else if identifier == ObjectFooterLogical::identifier() {
			2
		} else {
			0
		}
	}

	/// decodes the length of the header.
	fn decode_header_length<R: Read>(data: &mut R) -> Result<u64> {
		match data.read_u64::<LittleEndian>() {
			Ok(value) => Ok(value),
			Err(_) => Err(ZffError::new_header_decode_error(ERROR_HEADER_DECODER_HEADER_LENGTH)),
		}
	}

	/// Reads the data from the given [Reader](std::io::Read) and returns a decoded object footer.
	/// Returns an error, if the decoding process fails.
	pub fn decode_directly<R: Read>(data: &mut R) -> Result<ObjectFooter> {
		match Self::check_identifier(data) {
			1 => {
				let length = Self::decode_header_length(data)? as usize;
				let mut content_buffer = vec![0u8; length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
				data.read_exact(&mut content_buffer)?;
				Ok(ObjectFooter::Physical(ObjectFooterPhysical::decode_content(content_buffer)?))
			},
			2 => {
				let length = Self::decode_header_length(data)? as usize;
				let mut content_buffer = vec![0u8; length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
				data.read_exact(&mut content_buffer)?;
				Ok(ObjectFooter::Logical(ObjectFooterLogical::decode_content(content_buffer)?))
			},
			_ => Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER)),
		}
	}
}

/// An [ObjectFooterPhysical] is written at the end of each physical object.
/// This footer contains various information about the acquisition process:
/// - the acquisition start time
/// - the acquisition start time
/// - the size of the (uncompressed and unencrypted) underlying data
/// - the first chunk number, which is used for this physical dump
/// - the total number of chunks, used for this physical dump
/// - a hash header with the appropriate hash values of the underlying physical dump
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
	/// creates a new [ObjectFooterPhysical] with the given values.
	pub fn new(version: u8, acquisition_start: u64, acquisition_end: u64, length_of_data: u64, first_chunk_number: u64, number_of_chunks: u64, hash_header: HashHeader) -> ObjectFooterPhysical {
		Self {
			version,
			acquisition_start,
			acquisition_end,
			length_of_data,
			first_chunk_number,
			number_of_chunks,
			hash_header,
		}
	}

	/// returns the appropriate acquisition start time.
	pub fn acquisition_start(&self) -> u64 {
		self.acquisition_start
	}

	/// returns the appropriate acquisition start time.
	pub fn acquisition_end(&self) -> u64 {
		self.acquisition_end
	}

	/// returns the first chunk number, which is used for this physical dump.
	pub fn first_chunk_number(&self) -> u64 {
		self.first_chunk_number
	}

	/// returns the total number of chunks, used for this physical dump.
	pub fn number_of_chunks(&self) -> u64 {
		self.number_of_chunks
	}

	/// returns the size of the (uncompressed and unencrypted) underlying data.
	pub fn length_of_data(&self) -> u64 {
		self.length_of_data
	}

	/// returns a hash header with the appropriate hash values of the underlying physical dump.
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
		let mut vec = vec![self.version];
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

/// An [ObjectFooterLogical] is written at the end of each logical object container.
/// This footer contains various information about the acquisition process:
/// - the acquisition start time
/// - the acquisition start time
/// - a [Vec] of the filenumbers of the appropriate files in the root directory
/// - a [HashMap] in which segment numbers the corresponding file headers can be found.
/// - a [HashMap] in which offsets of the corresponding file headers can be found.
/// - a [HashMap] in which segment numbers the corresponding file footers can be found.
/// - a [HashMap] in which offsets the corresponding file footers can be found.
#[derive(Debug,Clone)]
pub struct ObjectFooterLogical {
	version: u8,
	acquisition_start: u64,
	acquisition_end: u64,
	root_dir_filenumbers: Vec<u64>,
	file_header_segment_numbers: HashMap<u64, u64>,
	file_header_offsets: HashMap<u64, u64>,
	file_footer_segment_numbers: HashMap<u64, u64>,
	file_footer_offsets: HashMap<u64, u64>,
}

impl ObjectFooterLogical {
	/// creates a new empty [ObjectFooterLogical]
	pub fn new_empty(version: u8) -> ObjectFooterLogical {
		Self {
			version,
			acquisition_start: 0,
			acquisition_end: 0,
			root_dir_filenumbers: Vec::new(),
			file_header_segment_numbers: HashMap::new(),
			file_header_offsets: HashMap::new(),
			file_footer_segment_numbers: HashMap::new(),
			file_footer_offsets: HashMap::new()
		}
	}

	/// creates a new [ObjectFooterLogical] with the given values.
	pub fn new(
		version: u8,
		acquisition_start: u64,
		acquisition_end: u64,
		root_dir_filenumbers: Vec<u64>,
		file_header_segment_numbers: HashMap<u64, u64>,
		file_header_offsets: HashMap<u64, u64>,
		file_footer_segment_numbers: HashMap<u64, u64>,
		file_footer_offsets: HashMap<u64, u64>) -> ObjectFooterLogical {
		Self {
			version,
			acquisition_start,
			acquisition_end,
			root_dir_filenumbers,
			file_header_segment_numbers,
			file_header_offsets,
			file_footer_segment_numbers,
			file_footer_offsets,
		}
	}

	/// adds a new filenumber to the underlying [Vec] of the filenumbers of the appropriate files in the root directory.
	pub fn add_root_dir_filenumber(&mut self, filenumber: u64) {
		self.root_dir_filenumbers.push(filenumber)
	}

	/// returns the underlying [Vec] of the filenumbers of the appropriate files in the root directory as a reference.
	pub fn root_dir_filenumbers(&self) -> &Vec<u64> {
		&self.root_dir_filenumbers
	}

	/// adds a file number / segment number combination to the appropriate underlying [HashMap],
	/// which contains the appropriate segment numbers of the corresponding file headers.
	pub fn add_file_header_segment_number(&mut self, filenumber: u64, file_segment_number: u64) {
		self.file_header_segment_numbers.insert(filenumber, file_segment_number);
	}

	/// adds a file number / offset combination to the appropriate underlying [HashMap],
	/// which contains the appropriate offsets of the corresponding file headers.
	pub fn add_file_header_offset(&mut self, filenumber: u64, fileoffset: u64) {
		self.file_header_offsets.insert(filenumber, fileoffset);
	}

	/// returns the underlying [HashMap], which contains the segment numbers and the corresponding file headers.
	pub fn file_header_segment_numbers(&self) -> &HashMap<u64, u64> {
		&self.file_header_segment_numbers
	}

	/// returns the underlying [HashMap], which contains the offsets and the corresponding file headers.
	pub fn file_header_offsets(&self) -> &HashMap<u64, u64> {
		&self.file_header_offsets
	}

	/// adds a file number / segment number combination to the appropriate underlying [HashMap],
	/// which contains the appropriate segment numbers of the corresponding file footers.
	pub fn add_file_footer_segment_number(&mut self, filenumber: u64, file_segment_number: u64) {
		self.file_footer_segment_numbers.insert(filenumber, file_segment_number);
	}

	/// adds a file number / offset combination to the appropriate underlying [HashMap],
	/// which contains the appropriate offsets of the corresponding file footers.
	pub fn add_file_footer_offset(&mut self, filenumber: u64, fileoffset: u64) {
		self.file_footer_offsets.insert(filenumber, fileoffset);
	}

	/// returns the underlying [HashMap], which contains the segment numbers and the corresponding file footers.
	pub fn file_footer_segment_numbers(&self) -> &HashMap<u64, u64> {
		&self.file_footer_segment_numbers
	}

	/// returns the underlying [HashMap], which contains the offsets and the corresponding file footers.
	pub fn file_footer_offsets(&self) -> &HashMap<u64, u64> {
		&self.file_footer_offsets
	}

	/// returns the acquisition start time.
	pub fn acquisition_start(&self) -> u64 {
		self.acquisition_start
	}

	/// returns the acquisition end time.
	pub fn acquisition_end(&self) -> u64 {
		self.acquisition_end
	}

	/// sets the acquisition start time.
	pub fn set_acquisition_start(&mut self, start: u64) {
		self.acquisition_start = start;
	}

	/// sets the acquisition end time.
	pub fn set_acquisition_end(&mut self, end: u64) {
		self.acquisition_end = end;
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
		let mut vec = vec![self.version];
		vec.append(&mut self.acquisition_start.encode_directly());
		vec.append(&mut self.acquisition_end.encode_directly());
		vec.append(&mut self.root_dir_filenumbers.encode_directly());
		vec.append(&mut self.file_header_segment_numbers.encode_directly());
		vec.append(&mut self.file_header_offsets.encode_directly());
		vec.append(&mut self.file_footer_segment_numbers.encode_directly());
		vec.append(&mut self.file_footer_offsets.encode_directly());
		vec
	}
	fn decode_content(data: Vec<u8>) -> Result<ObjectFooterLogical> {
		let mut cursor = Cursor::new(data);
		let footer_version = u8::decode_directly(&mut cursor)?;
		let acquisition_start = u64::decode_directly(&mut cursor)?;
		let acquisition_end = u64::decode_directly(&mut cursor)?;
		let root_dir_filenumbers = Vec::<u64>::decode_directly(&mut cursor)?;
		let file_header_segment_numbers = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		let file_header_offsets = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		let file_footer_segment_numbers = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		let file_footer_offsets = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		Ok(ObjectFooterLogical::new(footer_version, acquisition_start, acquisition_end, root_dir_filenumbers, file_header_segment_numbers, file_header_offsets, file_footer_segment_numbers, file_footer_offsets))
	}

}