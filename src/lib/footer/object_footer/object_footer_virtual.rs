// - Parent
use super::*;

/// An [ObjectFooterVirtual] is written at the end of an virtual logical object.
/// This footer contains various information about the underlying virtual files:
/// - information about the underlying folder structure
/// - appropriate file headers and [VirtualFileFooter] for each virtual file
#[derive(Debug,Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ObjectFooterVirtual {
    /// The object number of the footer.
    pub object_number: u64,
    /// UNIX timestamp when the creation of this objects has started.
    pub creation_timestamp: u64,
    /// A list of all objects which are affected by this virtual object.
    /// This is mostly necessary to identify affected objects in case of 
    /// encryption.
	pub passive_objects: Vec<u64>,
    /// The file numbers of the virtual object's root directories.
    pub root_dir_filenumbers: Vec<u64>,
    /// Maps a file number to the segment number containing its [FileHeader].
    pub file_header_segment_numbers: HashMap<u64, u64>,
    /// Maps a file number to the byte offset of its [FileHeader] inside the
    /// corresponding segment.
    pub file_header_offsets: HashMap<u64, u64>,
    /// instead of file_footer_offsets pointing to classic FileFooter only,
    /// point to a new virtual logical file footer.
    /// The classic FileFooter contains several necessary metadata, thus using
    /// a virtual logical file footer is necessary.
    /// Maps a file number to the segment number containing its
    /// [VirtualFileFooter].
    pub file_footer_segment_numbers: HashMap<u64, u64>,
    /// Maps a file number to the byte offset of its [VirtualFileFooter]
    /// inside the corresponding segment.
    pub file_footer_offsets: HashMap<u64, u64>,
}

impl ObjectFooterVirtual {
	/// Creates a new empty [ObjectFooterVirtual] with the given object number.
	pub fn new_empty(object_number: u64) -> Self {
		Self {
			object_number,
			..Default::default()
		}
	}
	/// Creates a new [ObjectFooterVirtual] from the object metadata and the
	/// location maps for the contained virtual files.
	#[allow(clippy::too_many_arguments)]
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
		vec.extend_from_slice(&self.creation_timestamp.encode_directly());
		vec.extend_from_slice(&self.passive_objects.encode_directly());
		vec.extend_from_slice(&self.root_dir_filenumbers.encode_directly());
		vec.extend_from_slice(&self.file_header_segment_numbers.encode_directly());
		vec.extend_from_slice(&self.file_header_offsets.encode_directly());
        vec.extend_from_slice(&self.file_footer_segment_numbers.encode_directly());
		vec.extend_from_slice(&self.file_footer_offsets.encode_directly());
		vec
	}

	/// Encrypts and encodes this object footer using the given encryption
	/// information.
	///
	/// # Error
	/// Returns an error if encryption fails.
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
		vec.extend_from_slice(&identifier.to_be_bytes());
		vec.extend_from_slice(&encoded_header_length.encode_directly());
		vec.extend_from_slice(&Self::version().encode_directly());
		vec.extend_from_slice(&self.object_number.encode_directly());
		vec.extend_from_slice(&true.encode_directly()); // encryption flag
		vec.extend_from_slice(&encrypted_content.encode_directly());

		Ok(vec)
	}

	#[allow(clippy::type_complexity)]
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
impl fmt::Display for ObjectFooterVirtual {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", Self::struct_name())
	}
}

impl HeaderCoding for ObjectFooterVirtual {
	type Item = Self;
	fn version() -> u8 { 
		DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_VIRTUAL
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_OBJECT_FOOTER_VIRTUAL
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![Self::version()];
		vec.extend_from_slice(&self.object_number.encode_directly());
		vec.extend_from_slice(&false.encode_directly()); // encryption flag
		vec.extend_from_slice(&self.encode_content());
		vec
	}
	fn decode_content(data: &[u8]) -> Result<Self> {
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
		"ObjectFooterVirtual"
	}
}

/// An object footer for a virtual object in encrypted form.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct EncryptedObjectFooterVirtual {
	/// The appropriate object number.
	pub object_number: u64,
	#[cfg_attr(feature = "serde", serde(serialize_with = "crate::helper::buffer_to_hex", deserialize_with = "crate::helper::hex_to_buffer"))]
	/// the encrypted data of this footer
	pub encrypted_data: Vec<u8>,
}

impl EncryptedObjectFooterVirtual {
	/// Creates a new [EncryptedObjectFooterVirtual] by the given values.
	pub fn new(object_number: u64, encrypted_data: Vec<u8>) -> Self {
		Self {
			object_number,
			encrypted_data,
		}
	}

	/// Tries to decrypt the ObjectFooter. If an error occures, the EncryptedObjectFooterPhysical is still available.
	pub fn decrypt<A, K>(&self, key: K, algorithm: A) -> Result<ObjectFooterVirtual>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		let content = ObjectFooter::decrypt(key, &self.encrypted_data, self.object_number, algorithm.borrow())?;
		let mut cursor = Cursor::new(content);
		let (creation_timestamp,
			passive_objects,
			root_dir_filenumbers,
			file_header_segment_numbers,
			file_header_offsets,
			file_footer_segment_numbers,
			file_footer_offsets) = ObjectFooterVirtual::decode_inner_content(&mut cursor)?;
		Ok(ObjectFooterVirtual::with_data(
			self.object_number,
			creation_timestamp, 
			passive_objects, 
			root_dir_filenumbers, 
			file_header_segment_numbers, 
			file_header_offsets, 
			file_footer_segment_numbers, 
			file_footer_offsets))
	}

	/// Tries to decrypt the ObjectFooter. Consumes the EncryptedObjectFooterPhysical, regardless of whether an error occurs or not.
	pub fn decrypt_and_consume<A, K>(self, key: K, algorithm: A) -> Result<ObjectFooterVirtual>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		self.decrypt(key, algorithm)
	}
}

// - implement fmt::Display
impl fmt::Display for EncryptedObjectFooterVirtual {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", Self::struct_name())
	}
}

impl HeaderCoding for EncryptedObjectFooterVirtual {
	type Item = Self;
	fn version() -> u8 { 
		DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_VIRTUAL
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_OBJECT_FOOTER_VIRTUAL
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![Self::version()];
		vec.extend_from_slice(&self.object_number.encode_directly());
		vec.extend_from_slice(&true.encode_directly()); // encryption flag
		vec.extend_from_slice(&self.encrypted_data.encode_directly());
		vec
	}
	fn decode_content(data: &[u8]) -> Result<Self> {
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
		"EncryptedObjectFooterVirtual"
	}
}