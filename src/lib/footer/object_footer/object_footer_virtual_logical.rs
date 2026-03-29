// - Parent
use super::*;

/// An [ObjectFooterVirtualLogical] is written at the end of an virtual logical object.
/// This footer contains various information about the underlying virtual files:
/// - information about the underlying folder structure
/// - appropriate file headers and [VirtualLogicalFileFooter] for each virtual file
#[derive(Debug,Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ObjectFooterVirtualLogical {
    /// The object number of the footer.
    pub object_number: u64,
    /// UNIX timestamp when the creation of this objects has started.
    pub creation_timestamp: u64,
    /// A list of all objects which are affected by this virtual object.
    /// This is mostly necessary to identify affected objects in case of 
    /// encryption.
	pub passive_objects: Vec<u64>,
    pub root_dir_filenumbers: Vec<u64>,
    pub file_header_segment_numbers: HashMap<u64, u64>,
    pub file_header_offsets: HashMap<u64, u64>,
    /// instead of file_footer_offsets pointing to classic FileFooter only,
    /// point to a new virtual logical file footer.
    /// The classic FileFooter contains several necessary metadata, thus using
    /// a virtual logical file footer is necessary.
    pub file_footer_segment_numbers: HashMap<u64, u64>,
    pub file_footer_offsets: HashMap<u64, u64>,
}

impl ObjectFooterVirtualLogical {
	/// creates a new [ObjectFooterVirtualLogical] with the given values.
	pub fn with_data(object_number: u64, 
		creation_timestamp: u64, 
		passive_objects: Vec<u64>,
		root_dir_filenumbers: Vec<u64>,
		file_header_segment_numbers: HashMap<u64, u64>,
        file_header_offsets: HashMap<u64, u64>,
        file_footer_segment_numbers: HashMap<u64, u64>,
        file_footer_offsets: HashMap<u64, u64>,) -> Self {
		Self {
			object_number,
			creation_timestamp,
			passive_objects,
			root_dir_filenumbers,
			file_header_segment_numbers,
			file_header_offsets,
            file_footer_segment_numbers,
            file_footer_offsets,
		}
	}

	fn encode_content(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.creation_timestamp.encode_directly());
		vec.append(&mut self.passive_objects.encode_directly());
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

	fn decode_inner_content<R: Read>(data: &mut R) -> Result<(
		u64, //creation_timestamp
		Vec<u64>, //passive_objects
		Vec<u64>, //root_dir filenumbers
        HashMap<u64, u64>, //file_header_segment_numbers
        HashMap<u64, u64>, //file_header_offsets
        HashMap<u64, u64>, //file_footer_segment_numbers
        HashMap<u64, u64>, //file_footer_offsets
		)> {
		let creation_timestamp = u64::decode_directly(data)?;
		let passive_objects = Vec::<u64>::decode_directly(data)?;
		let root_dir_filenumbers = Vec::<u64>::decode_directly(data)?;
        let file_header_segment_numbers = HashMap::<u64, u64>::decode_directly(data)?;
        let file_header_offsets = HashMap::<u64, u64>::decode_directly(data)?;
        let file_footer_segment_numbers = HashMap::<u64, u64>::decode_directly(data)?;
        let file_footer_offsets = HashMap::<u64, u64>::decode_directly(data)?;
		Ok((
			creation_timestamp,
			passive_objects,
			root_dir_filenumbers,
            file_header_segment_numbers,
            file_header_offsets,
            file_footer_segment_numbers,
            file_footer_offsets,
			))
	}
}

// - implement fmt::Display
impl fmt::Display for ObjectFooterVirtualLogical {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", Self::struct_name())
	}
}

impl HeaderCoding for ObjectFooterVirtualLogical {
	type Item = Self;
	fn version() -> u8 { 
		DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_VIRTUAL_LOGICAL
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_OBJECT_FOOTER_VIRTUAL_LOGICAL
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![Self::version()];
		vec.append(&mut self.object_number.encode_directly());
		vec.append(&mut false.encode_directly()); // encryption flag
		vec.append(&mut self.encode_content());
		vec
	}
	fn decode_content(data: Vec<u8>) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?;
		let object_number = u64::decode_directly(&mut cursor)?;
		let encryption_flag = bool::decode_directly(&mut cursor)?;
		if encryption_flag {
			return Err(ZffError::new(ZffErrorKind::EncodingError, ERROR_MISSING_ENCRYPTION_HEADER_KEY));
		}
		let (creation_timestamp,
			passive_objects,
			root_dir_filenumbers,
            file_header_segment_numbers,
            file_header_offsets,
            file_footer_segment_numbers,
            file_footer_offsets,) = Self::decode_inner_content(&mut cursor)?;
		Ok(Self::with_data(
			object_number,
			creation_timestamp, 
			passive_objects,
			root_dir_filenumbers,
			file_header_segment_numbers,
			file_header_offsets,
            file_footer_segment_numbers,
            file_footer_offsets))
	}

	fn struct_name() -> &'static str {
		"ObjectFooterVirtualLogical"
	}
}

#[derive(Debug,Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct VirtualLogicalFileFooter {
    pub file_number: u64,
    pub hash_header: HashHeader,
    pub length_of_data: u64,
    // where to find this file's mapping/extents
    pub file_map_segment_no: u64,
    pub file_map_offset: u64,
}

impl VirtualLogicalFileFooter {
	/// creates a new FileFooter by given values/hashes.
	pub fn new(
		file_number: u64,
		hash_header: HashHeader, 
		length_of_data: u64, 
		file_map_segment_no: u64, 
		file_map_offset: u64) -> Self {
		Self {
			file_number,
			hash_header,
			length_of_data,
			file_map_segment_no,
			file_map_offset,
		}
	}

	fn encode_content(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.hash_header.encode_directly());
		vec.append(&mut self.length_of_data.encode_directly());
		vec.append(&mut self.file_map_segment_no.encode_directly());
		vec.append(&mut self.file_map_offset.encode_directly());
		vec
	}

	/// encrypts the virtual logical file footer by the given encryption information and returns the encrypted file footer.
	/// # Error
	/// The method returns an error, if the encryption fails.
	pub fn encode_encrypted_header_directly<E>(&self, encryption_information: E) -> Result<Vec<u8>>
	where
		E: Borrow<EncryptionInformation>
	{
		let mut vec = Vec::new();
		let encryption_information = encryption_information.borrow();
		let mut encoded_footer = self.encode_encrypted_footer(&encryption_information.encryption_key, &encryption_information.algorithm)?;
		let identifier = Self::identifier();
		let encoded_header_length = 4 + 8 + (encoded_footer.len() as u64); //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.append(&mut encoded_footer);

		Ok(vec)
	}

	fn encode_encrypted_footer<K, A>(&self, key: K, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		let mut vec = Vec::new();
		vec.append(&mut Self::version().encode_directly());
		vec.append(&mut self.file_number.encode_directly());

		let mut data_to_encrypt = Vec::new();
		data_to_encrypt.append(&mut self.encode_content());

		let encrypted_data = FileFooter::encrypt(
			key, data_to_encrypt,
			self.file_number,
			algorithm
			)?;
		vec.append(&mut encrypted_data.encode_directly());
		Ok(vec)
	}

	/// decodes the encrypted header with the given key and [crate::header::EncryptionHeader].
	/// The appropriate [crate::header::EncryptionHeader] has to be stored in the appropriate [crate::header::ObjectHeader].
	pub fn decode_encrypted_footer_with_key<R, E>(data: &mut R, encryption_information: E) -> Result<Self>
	where
		R: Read,
		E: Borrow<EncryptionInformation>
	{
		if !Self::check_identifier(data) {
			return Err(ZffError::new(ZffErrorKind::Invalid, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER));
		};
		let header_length = Self::decode_header_length(data)? as usize;
		let mut header_content = vec![0u8; header_length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
		data.read_exact(&mut header_content)?;
		let mut cursor = Cursor::new(header_content);
		Self::check_version(&mut cursor)?;
		let file_number = u64::decode_directly(&mut cursor)?;
		let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
		let algorithm = &encryption_information.borrow().algorithm;
		let decrypted_data = FileFooter::decrypt(
			&encryption_information.borrow().encryption_key, 
			encrypted_data, 
			file_number, 
			algorithm)?;
		let mut cursor = Cursor::new(decrypted_data);
		let (hash_header, length_of_data, file_map_segment_no, file_map_offset) = Self::decode_inner_content(&mut cursor)?;
		Ok(Self::new(file_number, hash_header, length_of_data, file_map_segment_no, file_map_offset))
	}

	#[allow(clippy::type_complexity)]
	fn decode_inner_content<R: Read>(inner_content: &mut R) -> Result<(
		HashHeader, //HashHeader
		u64, //length_of_data
		u64, // file_map_segment_no,
		u64, // file_map_offset
		)> {
		let hash_header = HashHeader::decode_directly(inner_content)?;
		let length_of_data = u64::decode_directly(inner_content)?;
		let file_map_segment_no = u64::decode_directly(inner_content)?;
		let file_map_offset = u64::decode_directly(inner_content)?;

		let inner_content = (
			hash_header,
			length_of_data,
			file_map_segment_no,
			file_map_offset);
		Ok(inner_content)
	}
}

impl HeaderCoding for VirtualLogicalFileFooter {
	type Item = Self;
	fn version() -> u8 { 
		DEFAULT_FOOTER_VERSION_VIRTUAL_FILE_FOOTER
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_VIRTUAL_LOGICAL_FILE_FOOTER
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![Self::version()];
		vec.append(&mut self.file_number.encode_directly());
		vec.append(&mut self.encode_content());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?;
		let file_number = u64::decode_directly(&mut cursor)?;
		let (hash_header, length_of_data, file_map_segment_no, file_map_offset) = Self::decode_inner_content(&mut cursor)?;
		Ok(Self::new(file_number, hash_header, length_of_data, file_map_segment_no, file_map_offset))
	}

	fn struct_name() -> &'static str {
		"VirtualLogicalFileFooter"
	}
}

#[derive(Debug,Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct VirtualLogicalFileMap {
    /// A map with the offset parts of the virtual file and the appropriate
    /// mapping.
    pub extents: BTreeMap<u64, VirtualLogicalFileExtent>, // file_offset -> extent
}

impl VirtualLogicalFileMap {
	pub fn new(extents: BTreeMap<u64, VirtualLogicalFileExtent>) -> Self {
		Self {
			extents
		}
	}
}

impl HeaderCoding for VirtualLogicalFileMap {
	type Item = Self;
	fn version() -> u8 { 
		DEFAULT_FOOTER_VERSION_VIRTUAL_LOGICAL_FILE_MAP
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_VIRTUAL_LOGICAL_FILE_MAP
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![Self::version()];
		vec.append(&mut self.extents.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?;
		let extents = BTreeMap::<u64, VirtualLogicalFileExtent>::decode_directly(&mut cursor)?;
		Ok(Self::new(extents))
	}

	fn struct_name() -> &'static str {
		"VirtualLogicalFileMap"
	}
}


#[derive(Debug,Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct VirtualLogicalFileExtent {
    /// The appropriate source object of the underlying data
    pub source_object_number: u64,
    /// The appropriate source file number of the underlying data
    pub source_file_number: u64,
    /// The appropriate source offset at which the data section starts and from which it should be read.
    pub source_offset: u64,
    /// The length of this data section (**must** always be >=1!).
    pub length: u64,
}

impl VirtualLogicalFileExtent {
	pub fn new(source_object_number: u64, source_file_number: u64, source_offset: u64, length: u64) -> Self {
		Self {
			source_object_number,
			source_file_number,
			source_offset,
			length,
		}
	}
}

impl ValueEncoder for VirtualLogicalFileExtent {
	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_VLFE	
	}

	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = vec![];
		vec.append(&mut self.source_object_number.encode_directly());
		vec.append(&mut self.source_file_number.encode_directly());
		vec.append(&mut self.source_offset.encode_directly());
		vec.append(&mut self.length.encode_directly());
		vec
	}
}

impl ValueDecoder for VirtualLogicalFileExtent {
	type Item = Self;

	fn decode_directly<R: Read>(data: &mut R) -> Result<Self::Item> {
		let source_object_number = u64::decode_directly(data)?;
		let source_file_number = u64::decode_directly(data)?;
		let source_offset = u64::decode_directly(data)?;
		let length = u64::decode_directly(data)?;
		Ok(Self::new(source_object_number, source_file_number, source_offset, length))
	}
}