
// - internal
use super::*;

/// An [ObjectFooterLogical] is written at the end of each logical object container.
/// This footer contains various information about the acquisition process:
/// - the acquisition start time
/// - the acquisition start time
/// - a [Vec] of the filenumbers of the appropriate files in the root directory
/// - a [HashMap] in which segment numbers the corresponding file headers can be found.
/// - a [HashMap] in which offsets of the corresponding file headers can be found.
/// - a [HashMap] in which segment numbers the corresponding file footers can be found.
/// - a [HashMap] in which offsets the corresponding file footers can be found.
#[derive(Debug,Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ObjectFooterLogical {
	/// The object number of the footer.
	pub object_number: u64,
	/// The acquisition start timestamp of the footer.
	pub acquisition_start: u64,
	/// The acquisition end timestamp of the footer.
	pub acquisition_end: u64,
	/// The filenumbers which are children of the root directory.
	pub root_dir_filenumbers: Vec<u64>,
	/// the segment number where the appropriate file header can be found.
	pub file_header_segment_numbers: HashMap<u64, u64>,
	/// the offset where the appropriate file header can be found.
	pub file_header_offsets: HashMap<u64, u64>,
	/// the segment number where the appropriate file footer can be found.
	pub file_footer_segment_numbers: HashMap<u64, u64>,
	/// the offset where the appropriate file footer can be found.
	pub file_footer_offsets: HashMap<u64, u64>,
}

impl ObjectFooterLogical {
	/// creates a new empty [ObjectFooterLogical]
	pub fn new_empty(object_number: u64) -> ObjectFooterLogical {
		Self {
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
		object_number: u64,
		acquisition_start: u64,
		acquisition_end: u64,
		root_dir_filenumbers: Vec<u64>,
		file_header_segment_numbers: HashMap<u64, u64>,
		file_header_offsets: HashMap<u64, u64>,
		file_footer_segment_numbers: HashMap<u64, u64>,
		file_footer_offsets: HashMap<u64, u64>) -> ObjectFooterLogical {
		Self {
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

	/// encrypts the object footer by the given encryption information and returns the encrypted object footer.
	pub fn encrypt_directly<E>(&self, encryption_information: E) -> Result<Vec<u8>>
	where
		E: Borrow<EncryptionInformation>
	{
		let mut vec = Vec::new();
		
		let encrypted_content = ObjectFooter::encrypt(
			&encryption_information.borrow().encryption_key, 
			self.encode_content(), 
			self.object_number, 
			&encryption_information.borrow().algorithm)?;
		let identifier = Self::identifier();
		let encoded_header_length = (
			DEFAULT_LENGTH_HEADER_IDENTIFIER + 
			DEFAULT_LENGTH_VALUE_HEADER_LENGTH + 
			Self::version().encode_directly().len() +
			self.object_number.encode_directly().len() +
			true.encode_directly().len() +
			encrypted_content.encode_directly().len()) as u64; //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.encode_directly());
		vec.append(&mut Self::version().encode_directly());
		vec.append(&mut self.object_number.encode_directly());
		vec.append(&mut true.encode_directly()); // encryption flag
		vec.append(&mut encrypted_content.encode_directly());

		Ok(vec)
	}

	#[allow(clippy::type_complexity)]
	pub(crate) fn decode_inner_content<R: Read>(data: &mut R) -> Result<(
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

// - implement fmt::Display
impl fmt::Display for ObjectFooterLogical {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", Self::struct_name())
	}
}

impl HeaderCoding for ObjectFooterLogical {
	type Item = ObjectFooterLogical;

	fn version() -> u8 { 
		DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_LOGICAL
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_OBJECT_FOOTER_LOGICAL
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![Self::version()];
		vec.append(&mut self.object_number.encode_directly());
		vec.append(&mut false.encode_directly()); // encryption flag
		vec.append(&mut self.encode_content());
		vec
	}
	fn decode_content(data: Vec<u8>) -> Result<ObjectFooterLogical> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?; // check version (and skip it)
		let object_number = u64::decode_directly(&mut cursor)?;
		let encryption_flag = bool::decode_directly(&mut cursor)?;
		if encryption_flag {
			return Err(ZffError::new(ZffErrorKind::EncodingError, ERROR_MISSING_ENCRYPTION_HEADER_KEY));
		}
		let (acquisition_start,
			acquisition_end,
			root_dir_filenumbers,
			file_header_segment_numbers,
			file_header_offsets,
			file_footer_segment_numbers,
			file_footer_offsets) = Self::decode_inner_content(&mut cursor)?;
		Ok(ObjectFooterLogical::new(
			object_number,
			acquisition_start, 
			acquisition_end, 
			root_dir_filenumbers, 
			file_header_segment_numbers, 
			file_header_offsets, 
			file_footer_segment_numbers, 
			file_footer_offsets))
	}

	fn struct_name() -> &'static str {
		"ObjectFooterLogical"
	}
}

/// An object footer for a logical object in encrypted form.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct EncryptedObjectFooterLogical {
	/// The appropriate object number.
	pub object_number: u64,
	#[cfg_attr(feature = "serde", serde(serialize_with = "crate::helper::buffer_to_hex", deserialize_with = "crate::helper::hex_to_buffer"))]
	/// the encrypted data of this footer
	pub encrypted_data: Vec<u8>,
}

impl EncryptedObjectFooterLogical {
	/// Creates a new [EncryptedObjectFooterLogical] by the given values.
	pub fn new(object_number: u64, encrypted_data: Vec<u8>) -> Self {
		Self {
			object_number,
			encrypted_data,
		}
	}

	/// Tries to decrypt the ObjectFooter. If an error occures, the EncryptedObjectFooterPhysical is still available.
	pub fn decrypt<A, K>(&self, key: K, algorithm: A) -> Result<ObjectFooterLogical>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		let content = ObjectFooter::decrypt(key, &self.encrypted_data, self.object_number, algorithm.borrow())?;
		let mut cursor = Cursor::new(content);
		let (acquisition_start,
			acquisition_end,
			root_dir_filenumbers,
			file_header_segment_numbers,
			file_header_offsets,
			file_footer_segment_numbers,
			file_footer_offsets) = ObjectFooterLogical::decode_inner_content(&mut cursor)?;
		Ok(ObjectFooterLogical::new(
			self.object_number,
			acquisition_start, 
			acquisition_end, 
			root_dir_filenumbers, 
			file_header_segment_numbers, 
			file_header_offsets, 
			file_footer_segment_numbers, 
			file_footer_offsets))
	}

	/// Tries to decrypt the ObjectFooter. Consumes the EncryptedObjectFooterPhysical, regardless of whether an error occurs or not.
	pub fn decrypt_and_consume<A, K>(self, key: K, algorithm: A) -> Result<ObjectFooterLogical>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		self.decrypt(key, algorithm)
	}
}

// - implement fmt::Display
impl fmt::Display for EncryptedObjectFooterLogical {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", Self::struct_name())
	}
}

impl HeaderCoding for EncryptedObjectFooterLogical {
	type Item = EncryptedObjectFooterLogical;
	fn version() -> u8 { 
		DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_LOGICAL
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_OBJECT_FOOTER_LOGICAL
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![Self::version()];
		vec.append(&mut self.object_number.encode_directly());
		vec.append(&mut true.encode_directly()); // encryption flag
		vec.append(&mut self.encrypted_data.encode_directly());
		vec
	}
	fn decode_content(data: Vec<u8>) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?; // check version (and skip it)
		let object_number = u64::decode_directly(&mut cursor)?;
		let encryption_flag = bool::decode_directly(&mut cursor)?;
		if !encryption_flag {
			return Err(ZffError::new(
				ZffErrorKind::EncryptionError, 
				ERROR_DECODE_UNENCRYPTED_OBJECT_WITH_DECRYPTION_FN));
		}
		let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
		Ok(Self::new(
			object_number,
			encrypted_data))
	}

	fn struct_name() -> &'static str {
		"EncryptedObjectFooterLogical"
	}
}