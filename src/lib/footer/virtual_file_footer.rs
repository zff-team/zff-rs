// - Parent
use super::*;

#[derive(Debug,Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct VirtualFileFooter {
    pub file_number: u64,
    pub hash_header: HashHeader,
    pub length_of_data: u64,
    // where to find this file's mapping/extents
    pub file_map_segment_no: u64,
    pub file_map_offset: u64,
}

impl VirtualFileFooter {
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

impl HeaderCoding for VirtualFileFooter {
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
		"VirtualFileFooter"
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