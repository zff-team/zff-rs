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