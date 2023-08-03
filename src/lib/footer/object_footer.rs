// - STD
use core::borrow::Borrow;
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
	Encryption,
	EncryptionAlgorithm,
	FOOTER_IDENTIFIER_OBJECT_FOOTER_PHYSICAL,
	FOOTER_IDENTIFIER_OBJECT_FOOTER_LOGICAL,
	DEFAULT_LENGTH_VALUE_HEADER_LENGTH,
	DEFAULT_LENGTH_HEADER_IDENTIFIER,
	ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER,
	ERROR_HEADER_DECODER_HEADER_LENGTH,
};
use crate::header::{
	HashHeader,
	EncryptionInformation,
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

impl From<ObjectFooterPhysical> for ObjectFooter {
	fn from(footer: ObjectFooterPhysical) -> Self {
		ObjectFooter::Physical(footer)
	}
}

impl From<ObjectFooterLogical> for ObjectFooter {
	fn from(footer: ObjectFooterLogical) -> Self {
		ObjectFooter::Logical(footer)
	}
}

/// Each object contains its own object footer (and this is the encrypted variant).
#[derive(Debug, Clone)]
pub enum EncryptedObjectFooter {
	/// A physical object contains a [EncryptedObjectFooterPhysical].
	Physical(EncryptedObjectFooterPhysical),
	/// A logical object contains a [EncryptedObjectFooterLogical].
	Logical(EncryptedObjectFooterLogical),
}

impl EncryptedObjectFooter {
	/// returns the version of the object footer.
	pub fn version(&self) -> u8 {
		match self {
			EncryptedObjectFooter::Physical(phy) => phy.version(),
			EncryptedObjectFooter::Logical(log) => log.version(),
		}
	}

	/// checks if the identifier matches to an physical or logical object footer. Returns 1 for a physical object footer, 2 for a logical object footer and 0 if neither applies.
	fn check_identifier<R: Read>(data: &mut R) -> u8 {
		let identifier = match data.read_u32::<BigEndian>() {
			Ok(val) => val,
			Err(_) => return 0,
		};
		if identifier == EncryptedObjectFooterPhysical::identifier() { 
			1
		} else if identifier == EncryptedObjectFooterLogical::identifier() {
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
	pub fn decode_directly<R: Read>(data: &mut R) -> Result<EncryptedObjectFooter> {
		match Self::check_identifier(data) {
			1 => {
				let length = Self::decode_header_length(data)? as usize;
				let mut content_buffer = vec![0u8; length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
				data.read_exact(&mut content_buffer)?;
				Ok(EncryptedObjectFooter::Physical(EncryptedObjectFooterPhysical::decode_content(content_buffer)?))
			},
			2 => {
				let length = Self::decode_header_length(data)? as usize;
				let mut content_buffer = vec![0u8; length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
				data.read_exact(&mut content_buffer)?;
				Ok(EncryptedObjectFooter::Logical(EncryptedObjectFooterLogical::decode_content(content_buffer)?))
			},
			_ => Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER)),
		}
	}

	/// tries to decrypt the ObjectFooter. If an error occures, the EncryptedObjectFooter is still available.
	pub fn decrypt<A, K>(&self, key: K, algorithm: A) -> Result<ObjectFooter>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		match self {
			EncryptedObjectFooter::Physical(encrypted_inner_footer) => {
				let decrypted_footer = encrypted_inner_footer.decrypt(key, algorithm)?;
				Ok(ObjectFooter::from(decrypted_footer))
			},
			EncryptedObjectFooter::Logical(encrypted_inner_footer) => {
				let decrypted_footer = encrypted_inner_footer.decrypt(key, algorithm)?;
				Ok(ObjectFooter::from(decrypted_footer))
			}
		}
	}

	/// tries to decrypt the ObjectFooter. Consumes the EncryptedObjectFooter, regardless of whether an error occurs or not.
	pub fn decrypt_and_consume<A, K>(self, key: K, algorithm: A) -> Result<ObjectFooter>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		match self {
			EncryptedObjectFooter::Physical(encrypted_inner_footer) => {
				let decrypted_footer = encrypted_inner_footer.decrypt_and_consume(key, algorithm)?;
				Ok(ObjectFooter::from(decrypted_footer))
			},
			EncryptedObjectFooter::Logical(encrypted_inner_footer) => {
				let decrypted_footer = encrypted_inner_footer.decrypt_and_consume(key, algorithm)?;
				Ok(ObjectFooter::from(decrypted_footer))
			}
		}
	}
}

/// Encrypted footer.
#[derive(Debug, Clone)]
pub struct EncryptedObjectFooterPhysical {
	pub version: u8,
	pub object_number: u64,
	pub encrypted_data: Vec<u8>,
}

impl EncryptedObjectFooterPhysical {
	pub fn new(version: u8, object_number: u64, encrypted_data: Vec<u8>) -> Self {
		Self {
			version,
			object_number,
			encrypted_data,
		}
	}

	/// tries to decrypt the ObjectFooter. If an error occures, the EncryptedObjectFooterPhysical is still available.
	pub fn decrypt<A, K>(&self, key: K, algorithm: A) -> Result<ObjectFooterPhysical>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		let content = Encryption::decrypt_object_footer(key, &self.encrypted_data, self.object_number, algorithm.borrow())?;
		let mut cursor = Cursor::new(content);
		let (acquisition_start, 
			acquisition_end, 
			length_of_data, 
			first_chunk_number, 
			number_of_chunks, 
			hash_header) = ObjectFooterPhysical::decode_inner_content(&mut cursor)?;
		Ok(ObjectFooterPhysical::new(
			self.version, 
			self.object_number,
			acquisition_start,
			acquisition_end,
			length_of_data,
			first_chunk_number,
			number_of_chunks,
			hash_header))
	}

	/// tries to decrypt the ObjectFooter. Consumes the EncryptedObjectFooterPhysical, regardless of whether an error occurs or not.
	pub fn decrypt_and_consume<A, K>(self, key: K, algorithm: A) -> Result<ObjectFooterPhysical>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		let content = Encryption::decrypt_object_footer(key, &self.encrypted_data, self.object_number, algorithm.borrow())?;
		let mut cursor = Cursor::new(content);
		let (acquisition_start, 
			acquisition_end, 
			length_of_data, 
			first_chunk_number, 
			number_of_chunks, 
			hash_header) = ObjectFooterPhysical::decode_inner_content(&mut cursor)?;
		Ok(ObjectFooterPhysical::new(
			self.version, 
			self.object_number,
			acquisition_start,
			acquisition_end,
			length_of_data,
			first_chunk_number,
			number_of_chunks,
			hash_header))
	}
}

impl HeaderCoding for EncryptedObjectFooterPhysical {
	type Item = EncryptedObjectFooterPhysical;
	fn version(&self) -> u8 { 
		self.version
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_OBJECT_FOOTER_PHYSICAL
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![self.version];
		vec.append(&mut self.object_number.encode_directly());
		vec.append(&mut self.encrypted_data.encode_directly());
		vec
	}
	fn decode_content(data: Vec<u8>) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		let footer_version = u8::decode_directly(&mut cursor)?;
		let object_number = u64::decode_directly(&mut cursor)?;
		let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
		Ok(Self::new(
			footer_version, 
			object_number,
			encrypted_data))
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
	pub version: u8,
	pub object_number: u64,
	pub acquisition_start: u64,
	pub acquisition_end: u64,
	pub length_of_data: u64,
	pub first_chunk_number: u64,
	pub number_of_chunks: u64,
	pub hash_header: HashHeader,
}

impl ObjectFooterPhysical {
	/// creates a new [ObjectFooterPhysical] with the given values.
	#[allow(clippy::too_many_arguments)]
	pub fn new(version: u8,
		object_number: u64, 
		acquisition_start: u64, 
		acquisition_end: u64, 
		length_of_data: u64, 
		first_chunk_number: u64, 
		number_of_chunks: u64, 
		hash_header: HashHeader) -> ObjectFooterPhysical {
		Self {
			version,
			object_number,
			acquisition_start,
			acquisition_end,
			length_of_data,
			first_chunk_number,
			number_of_chunks,
			hash_header,
		}
	}

	fn encode_content(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.acquisition_start.encode_directly());
		vec.append(&mut self.acquisition_end.encode_directly());
		vec.append(&mut self.length_of_data.encode_directly());
		vec.append(&mut self.first_chunk_number.encode_directly());
		vec.append(&mut self.number_of_chunks.encode_directly());
		vec.append(&mut self.hash_header.encode_directly());
		vec
	}

	pub fn encrypt_directly<E>(&self, encryption_information: E) -> Result<Vec<u8>>
	where
		E: Borrow<EncryptionInformation>
	{
		let mut vec = Vec::new();
		let mut encrypted_content = Encryption::encrypt_object_footer(
			&encryption_information.borrow().encryption_key, 
			self.encode_content(), 
			self.object_number, 
			&encryption_information.borrow().algorithm)?;
		let identifier = Self::identifier();
		let encoded_header_length = (DEFAULT_LENGTH_HEADER_IDENTIFIER + DEFAULT_LENGTH_VALUE_HEADER_LENGTH + encrypted_content.len()) as u64; //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.encode_directly());
		vec.append(&mut self.version.encode_directly());
		vec.append(&mut self.object_number.encode_directly());
		vec.append(&mut encrypted_content);

		Ok(vec)
	}

	fn decode_inner_content<R: Read>(data: &mut R) -> Result<(
		u64, //acquisition_start
		u64, //acquisition_end
		u64, //length_of_data
		u64, //first_chunk_number
		u64, //number_of_chunks
		HashHeader // hash_header
		)> {
		let acquisition_start = u64::decode_directly(data)?;
		let acquisition_end = u64::decode_directly(data)?;
		let length_of_data = u64::decode_directly(data)?;
		let first_chunk_number = u64::decode_directly(data)?;
		let number_of_chunks = u64::decode_directly(data)?;
		let hash_header = HashHeader::decode_directly(data)?;
		Ok((
			acquisition_start,
			acquisition_end,
			length_of_data,
			first_chunk_number,
			number_of_chunks,
			hash_header
			))
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
		vec.append(&mut self.object_number.encode_directly());
		vec.append(&mut self.encode_content());
		vec
	}
	fn decode_content(data: Vec<u8>) -> Result<ObjectFooterPhysical> {
		let mut cursor = Cursor::new(data);
		let footer_version = u8::decode_directly(&mut cursor)?;
		let object_number = u64::decode_directly(&mut cursor)?;
		let (acquisition_start, 
			acquisition_end, 
			length_of_data, 
			first_chunk_number, 
			number_of_chunks, 
			hash_header) = Self::decode_inner_content(&mut cursor)?;
		Ok(ObjectFooterPhysical::new(
			footer_version, 
			object_number,
			acquisition_start, 
			acquisition_end, 
			length_of_data, 
			first_chunk_number, 
			number_of_chunks, 
			hash_header))
	}
}

/// Encrypted footer.
#[derive(Debug, Clone)]
pub struct EncryptedObjectFooterLogical {
	pub version: u8,
	pub object_number: u64,
	pub encrypted_data: Vec<u8>,
}

impl EncryptedObjectFooterLogical {
	pub fn new(version: u8, object_number: u64, encrypted_data: Vec<u8>) -> Self {
		Self {
			version,
			object_number,
			encrypted_data,
		}
	}

	/// tries to decrypt the ObjectFooter. If an error occures, the EncryptedObjectFooterPhysical is still available.
	pub fn decrypt<A, K>(&self, key: K, algorithm: A) -> Result<ObjectFooterLogical>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		let content = Encryption::decrypt_object_footer(key, &self.encrypted_data, self.object_number, algorithm.borrow())?;
		let mut cursor = Cursor::new(content);
		let (acquisition_start,
			acquisition_end,
			root_dir_filenumbers,
			file_header_segment_numbers,
			file_header_offsets,
			file_footer_segment_numbers,
			file_footer_offsets) = ObjectFooterLogical::decode_inner_content(&mut cursor)?;
		Ok(ObjectFooterLogical::new(
			self.version, 
			self.object_number,
			acquisition_start, 
			acquisition_end, 
			root_dir_filenumbers, 
			file_header_segment_numbers, 
			file_header_offsets, 
			file_footer_segment_numbers, 
			file_footer_offsets))
	}

	/// tries to decrypt the ObjectFooter. Consumes the EncryptedObjectFooterPhysical, regardless of whether an error occurs or not.
	pub fn decrypt_and_consume<A, K>(self, key: K, algorithm: A) -> Result<ObjectFooterLogical>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		let content = Encryption::decrypt_object_footer(key, &self.encrypted_data, self.object_number, algorithm.borrow())?;
		let mut cursor = Cursor::new(content);
		let (acquisition_start,
			acquisition_end,
			root_dir_filenumbers,
			file_header_segment_numbers,
			file_header_offsets,
			file_footer_segment_numbers,
			file_footer_offsets) = ObjectFooterLogical::decode_inner_content(&mut cursor)?;
		Ok(ObjectFooterLogical::new(
			self.version, 
			self.object_number,
			acquisition_start, 
			acquisition_end, 
			root_dir_filenumbers, 
			file_header_segment_numbers, 
			file_header_offsets, 
			file_footer_segment_numbers, 
			file_footer_offsets))
	}
}

impl HeaderCoding for EncryptedObjectFooterLogical {
	type Item = EncryptedObjectFooterLogical;
	fn version(&self) -> u8 { 
		self.version
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_OBJECT_FOOTER_LOGICAL
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![self.version];
		vec.append(&mut self.object_number.encode_directly());
		vec.append(&mut self.encrypted_data.encode_directly());
		vec
	}
	fn decode_content(data: Vec<u8>) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		let footer_version = u8::decode_directly(&mut cursor)?;
		let object_number = u64::decode_directly(&mut cursor)?;
		let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
		Ok(Self::new(
			footer_version, 
			object_number,
			encrypted_data))
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
	object_number: u64,
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
	pub fn new_empty(version: u8, object_number: u64) -> ObjectFooterLogical {
		Self {
			version,
			object_number,
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
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		version: u8,
		object_number: u64,
		acquisition_start: u64,
		acquisition_end: u64,
		root_dir_filenumbers: Vec<u64>,
		file_header_segment_numbers: HashMap<u64, u64>,
		file_header_offsets: HashMap<u64, u64>,
		file_footer_segment_numbers: HashMap<u64, u64>,
		file_footer_offsets: HashMap<u64, u64>) -> ObjectFooterLogical {
		Self {
			version,
			object_number,
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

	fn encode_content(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.acquisition_start.encode_directly());
		vec.append(&mut self.acquisition_end.encode_directly());
		vec.append(&mut self.root_dir_filenumbers.encode_directly());
		vec.append(&mut self.file_header_segment_numbers.encode_directly());
		vec.append(&mut self.file_header_offsets.encode_directly());
		vec.append(&mut self.file_footer_segment_numbers.encode_directly());
		vec.append(&mut self.file_footer_offsets.encode_directly());
		vec
	}

	pub fn encrypt_directly<E>(&self, encryption_information: E) -> Result<Vec<u8>>
	where
		E: Borrow<EncryptionInformation>
	{
		let mut vec = Vec::new();
		let mut encrypted_content = Encryption::encrypt_object_footer(
			&encryption_information.borrow().encryption_key, 
			self.encode_content(), 
			self.object_number, 
			&encryption_information.borrow().algorithm)?;
		let identifier = Self::identifier();
		let encoded_header_length = (DEFAULT_LENGTH_HEADER_IDENTIFIER + DEFAULT_LENGTH_VALUE_HEADER_LENGTH + encrypted_content.len()) as u64; //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.encode_directly());
		vec.append(&mut self.version.encode_directly());
		vec.append(&mut self.object_number.encode_directly());
		vec.append(&mut encrypted_content);

		Ok(vec)
	}

	#[allow(clippy::type_complexity)]
	fn decode_inner_content<R: Read>(data: &mut R) -> Result<(
		u64, //acquisition_start
		u64, //acquisition_end
		Vec<u64>, //root_dir_filenumbers
		HashMap<u64, u64>, //file_header_segment_numbers
		HashMap<u64, u64>, //file_header_offsets
		HashMap<u64, u64>, //file_footer_segment_numbers
		HashMap<u64, u64>, //file_footer_offsets
		)> {
		let acquisition_start = u64::decode_directly(data)?;
		let acquisition_end = u64::decode_directly(data)?;
		let root_dir_filenumbers = Vec::<u64>::decode_directly(data)?;
		let file_header_segment_numbers = HashMap::<u64, u64>::decode_directly(data)?;
		let file_header_offsets = HashMap::<u64, u64>::decode_directly(data)?;
		let file_footer_segment_numbers = HashMap::<u64, u64>::decode_directly(data)?;
		let file_footer_offsets = HashMap::<u64, u64>::decode_directly(data)?;
		Ok((
			acquisition_start,
			acquisition_end,
			root_dir_filenumbers,
			file_header_segment_numbers,
			file_header_offsets,
			file_footer_segment_numbers,
			file_footer_offsets
			))
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
		vec.append(&mut self.object_number.encode_directly());
		vec.append(&mut self.encode_content());
		vec
	}
	fn decode_content(data: Vec<u8>) -> Result<ObjectFooterLogical> {
		let mut cursor = Cursor::new(data);
		let footer_version = u8::decode_directly(&mut cursor)?;
		let object_number = u64::decode_directly(&mut cursor)?;
		let (acquisition_start,
			acquisition_end,
			root_dir_filenumbers,
			file_header_segment_numbers,
			file_header_offsets,
			file_footer_segment_numbers,
			file_footer_offsets) = Self::decode_inner_content(&mut cursor)?;
		Ok(ObjectFooterLogical::new(
			footer_version, 
			object_number,
			acquisition_start, 
			acquisition_end, 
			root_dir_filenumbers, 
			file_header_segment_numbers, 
			file_header_offsets, 
			file_footer_segment_numbers, 
			file_footer_offsets))
	}

}