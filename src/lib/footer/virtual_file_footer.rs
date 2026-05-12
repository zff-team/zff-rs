// - Parent
use super::*;

/// Encodes the type-specific content stored in a [VirtualFileFooter].
///
/// For regular virtual files this stores the location of the serialized
/// [VirtualFileMap], while other variants carry the data needed to represent
/// directories, links, and special files directly in the footer (inline).
#[derive(Debug,Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum VirtualFileFooterContent {
	/// Contains the (segment_no, offset) tuple of the corresponding serialized
	/// [`VirtualFileMap`].
	FileMap(u64, u64),
	/// Contains the file numbers of all direct children of the directory.
	Directory(Vec<u64>),
	/// Contains the symlink target path.
	Symlink(PlatformString),
	/// Contains the file number of the referenced hardlink target.
	Hardlink(u64),
	/// Contains the merged rdev identifier and the corresponding special file
	/// type.
	SpecialFile(u64, SpecialFileType)
}

impl From<VirtualFileContent> for VirtualFileFooterContent {
	fn from(value: VirtualFileContent) -> Self {
		match value {
			VirtualFileContent::Directory(value) => Self::Directory(value),
			VirtualFileContent::FileMap(_) => Self::FileMap(0, 0),
			VirtualFileContent::FileMapPosition(seg, off) => Self::FileMap(seg, off),
			VirtualFileContent::Hardlink(value) => Self::Hardlink(value),
			VirtualFileContent::SpecialFile(val1, val2) => Self::SpecialFile(val1, val2),
			VirtualFileContent::Symlink(value) => Self::Symlink(value),
		}
	}
}

impl VirtualFileFooterContent {
	fn flag(&self) -> u8 {
		match self {
			VirtualFileFooterContent::FileMap(_, _) => VIRTUALFILEFOOTERCONTENT_VFM,
			VirtualFileFooterContent::Directory(_) => VIRTUALFILEFOOTERCONTENT_DIRECTORY,
			VirtualFileFooterContent::Symlink(_) => VIRTUALFILEFOOTERCONTENT_SYMLINK,
			VirtualFileFooterContent::Hardlink(_) => VIRTUALFILEFOOTERCONTENT_HARDLINK,
			VirtualFileFooterContent::SpecialFile(_, _) => VIRTUALFILEFOOTERCONTENT_SPECIAL_FILE,
		}
	}

	fn encode_content(&self) -> Vec<u8> {
		match self {
			VirtualFileFooterContent::FileMap(segment_no, offset) => {
				let mut vec = segment_no.encode_directly();
				vec.extend_from_slice(&offset.encode_directly());
				vec
			},
			VirtualFileFooterContent::Directory(filenumbers) => filenumbers.encode_directly(),
			VirtualFileFooterContent::Symlink(symlink) => symlink.encode_directly(),
			VirtualFileFooterContent::Hardlink(hardlink) => hardlink.encode_directly(),
			VirtualFileFooterContent::SpecialFile(rdev_id, stype) => {
				let mut vec = rdev_id.encode_directly();
				vec.extend_from_slice(&(*stype as u8).encode_directly());
				vec
			}
		}
	}
}

impl ValueEncoder for VirtualFileFooterContent {
	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_VFFC
	}

	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = self.flag().encode_directly();
		vec.extend_from_slice(&self.encode_content());
		vec
	}

	fn encoded_size(&self) -> usize {
		1 + match self {
			VirtualFileFooterContent::FileMap(segment_no, offset) => {
				segment_no.encoded_size() + offset.encoded_size()
			},
			VirtualFileFooterContent::Directory(filenumbers) => filenumbers.encoded_size(),
			VirtualFileFooterContent::Symlink(symlink) => symlink.encoded_size(),
			VirtualFileFooterContent::Hardlink(hardlink) => hardlink.encoded_size(),
			VirtualFileFooterContent::SpecialFile(rdev_id, stype) => {
				rdev_id.encoded_size() + (*stype as u8).encoded_size()
			},
		}
	}
}

impl ValueDecoder for VirtualFileFooterContent {
	type Item = Self;

	fn decode_directly<R: Read>(data: &mut R) -> Result<Self::Item> {
		let flag = u8::decode_directly(data)?;
		match flag {
			VIRTUALFILEFOOTERCONTENT_VFM =>  {
				let segment_no = u64::decode_directly(data)?;
				let offset = u64::decode_directly(data)?;
				Ok(Self::FileMap(segment_no, offset))
			},
			VIRTUALFILEFOOTERCONTENT_DIRECTORY => {
				let filenumbers = Vec::<u64>::decode_directly(data)?;
				Ok(Self::Directory(filenumbers))
			},
			VIRTUALFILEFOOTERCONTENT_SYMLINK => {
				let symlink_path = PlatformString::decode_directly(data)?;
				Ok(Self::Symlink(symlink_path))
			},
			VIRTUALFILEFOOTERCONTENT_HARDLINK => {
				let filenumber = u64::decode_directly(data)?;
				Ok(Self::Hardlink(filenumber))
			},
			VIRTUALFILEFOOTERCONTENT_SPECIAL_FILE => {
				let rdev_id = u64::decode_directly(data)?;
				let special_file_type = SpecialFileType::try_from(u8::decode_directly(data)?)?;
				Ok(Self::SpecialFile(rdev_id, special_file_type))
			},
			_ => Err(ZffError::new(ZffErrorKind::Invalid, ERROR_INVALID_TYPE_FLAG_VALUE)),
		}
	}
}

/// Footer of a virtual logical file.
///
/// This footer stores the virtual file's file number, hash metadata, logical
/// data length, and the type-specific [VirtualFileFooterContent].
#[derive(Debug,Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct VirtualFileFooter {
    /// The file number of the virtual file this footer belongs to.
    pub filenumber: u64,
    /// The hash information for the virtual file data.
    pub hash_header: HashHeader,
    /// The logical length of the represented file data in bytes.
    pub length_of_data: u64,
    /// The type-specific virtual file footer content.
    pub vffc: VirtualFileFooterContent,
}

impl VirtualFileFooter {
	/// Creates a new [VirtualFileFooter] from the file number, hash
	/// information, logical data length, and footer content.
	pub fn new(
		filenumber: u64,
		hash_header: HashHeader, 
		length_of_data: u64,
		vffc: VirtualFileFooterContent) -> Self {
		Self {
			filenumber,
			hash_header,
			length_of_data,
			vffc
		}
	}

	fn encode_content(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.extend_from_slice(&self.hash_header.encode_directly());
		vec.extend_from_slice(&self.length_of_data.encode_directly());
		vec.extend_from_slice(&self.vffc.encode_directly());
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
		let encoded_footer = self.encode_encrypted_footer(&encryption_information.encryption_key, &encryption_information.algorithm)?;
		let identifier = Self::identifier();
		let encoded_header_length = 4 + 8 + (encoded_footer.len() as u64); //4 bytes identifier + 8 bytes for length + length itself
		vec.extend_from_slice(&identifier.to_be_bytes());
		vec.extend_from_slice(&encoded_header_length.to_le_bytes());
		vec.extend_from_slice(&encoded_footer);

		Ok(vec)
	}

	fn encode_encrypted_footer<K, A>(&self, key: K, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		let mut vec = Vec::new();
		vec.extend_from_slice(&Self::version().encode_directly());
		vec.extend_from_slice(&self.filenumber.encode_directly());

		let mut data_to_encrypt = Vec::new();
		data_to_encrypt.append(&mut self.encode_content());

		let encrypted_data = VirtualFileFooter::encrypt(
			key, data_to_encrypt,
			self.filenumber,
			algorithm
			)?;
		vec.extend_from_slice(&encrypted_data.encode_directly());
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
		let filenumber = u64::decode_directly(&mut cursor)?;
		let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
		let algorithm = &encryption_information.borrow().algorithm;
		let decrypted_data = Self::decrypt(
			&encryption_information.borrow().encryption_key, 
			encrypted_data, 
			filenumber, 
			algorithm)?;
		let mut cursor = Cursor::new(decrypted_data);
		let (hash_header, length_of_data, vffc) = Self::decode_inner_content(&mut cursor)?;
		Ok(Self::new(filenumber, hash_header, length_of_data, vffc))
	}

	#[allow(clippy::type_complexity)]
	fn decode_inner_content<R: Read>(inner_content: &mut R) -> Result<(
		HashHeader, //HashHeader
		u64, //length_of_data
		VirtualFileFooterContent,
		)> {
		let hash_header = HashHeader::decode_directly(inner_content)?;
		let length_of_data = u64::decode_directly(inner_content)?;
		let vffc = VirtualFileFooterContent::decode_directly(inner_content)?;

		let inner_content = (
			hash_header,
			length_of_data,
			vffc);
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
		vec.extend_from_slice(&self.filenumber.encode_directly());
		vec.extend_from_slice(&self.encode_content());
		vec
	}

	fn decode_content(data: &[u8]) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?;
		let filenumber = u64::decode_directly(&mut cursor)?;
		let (hash_header, length_of_data, vffc) = Self::decode_inner_content(&mut cursor)?;
		Ok(Self::new(filenumber, hash_header, length_of_data, vffc))
	}

	fn struct_name() -> &'static str {
		"VirtualFileFooter"
	}
}

impl Encryption for VirtualFileFooter {
	fn crypto_nonce_padding() -> u8 {
		0b00001000 //TODO: move all crypto paddings to constants (#codeCleanup)
	}
}

/// Maps virtual file offsets to the source extents that provide the file's
/// logical data.
#[derive(Debug,Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct VirtualFileMap {
	/// The corresponding file number.
	pub filenumber: u64, // Note: The filenumber at this point seems redundant, but is necessary to calculate the encryption nonce.
    /// A map with the offset parts of the virtual file and the appropriate
    /// mapping.
    pub extents: BTreeMap<u64, VirtualFileExtent>, // file_offset -> extent
}

impl VirtualFileMap {
	/// Creates a new [`VirtualFileMap`] from the virtual file number and its
	/// extent mapping.
	pub fn new(filenumber: u64, extents: BTreeMap<u64, VirtualFileExtent>) -> Self {
		Self {
			filenumber,
			extents
		}
	}

	/// Encrypts and encodes this virtual file map using the given key and
	/// algorithm.
	///
	/// # Error
	/// Returns an error if encryption fails.
	pub fn encode_encrypted_footer<K, A>(&self, key: K, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		let mut vec = Vec::new();
		vec.extend_from_slice(&Self::version().encode_directly());
		vec.extend_from_slice(&self.filenumber.encode_directly());

		let mut data_to_encrypt = Vec::new();
		data_to_encrypt.append(&mut self.extents.encode_directly());

		let encrypted_data = Self::encrypt(
			key, data_to_encrypt,
			self.filenumber,
			algorithm
			)?;
		vec.extend_from_slice(&encrypted_data.encode_directly());
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
		let filenumber = u64::decode_directly(&mut cursor)?;
		let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
		let algorithm = &encryption_information.borrow().algorithm;
		let decrypted_data = Self::decrypt(
			&encryption_information.borrow().encryption_key, 
			encrypted_data, 
			filenumber, 
			algorithm)?;
		let mut cursor = Cursor::new(decrypted_data);
		let extends = BTreeMap::<u64, VirtualFileExtent>::decode_directly(&mut cursor)?;
		Ok(Self::new(filenumber, extends))
	}
}

impl HeaderCoding for VirtualFileMap {
	type Item = Self;
	fn version() -> u8 { 
		DEFAULT_FOOTER_VERSION_VIRTUAL_LOGICAL_FILE_MAP
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_VIRTUAL_LOGICAL_FILE_MAP
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![Self::version()];
		vec.extend_from_slice(&self.filenumber.encode_directly());
		vec.extend_from_slice(&self.extents.encode_directly());
		vec
	}

	fn decode_content(data: &[u8]) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?;
		let filenumber = u64::decode_directly(&mut cursor)?;
		let extents = BTreeMap::<u64, VirtualFileExtent>::decode_directly(&mut cursor)?;
		Ok(Self::new(filenumber, extents))
	}

	fn struct_name() -> &'static str {
		"VirtualFileMap"
	}
}

impl Encryption for VirtualFileMap {
	fn crypto_nonce_padding() -> u8 {
		0b01111111 //TODO: move all crypto paddings to constants (#codeCleanup)
	}
}

impl From<VirtualFileMap> for Vec<(u64, VirtualFileExtent)> {
	fn from(vlfm: VirtualFileMap) -> Self {
		let mut new_vec = Vec::new();
		for (virtual_offset, vlfe) in vlfm.extents {
			new_vec.push((virtual_offset, vlfe));
		}
		new_vec
	}
}

/// Maps a contiguous byte range of a virtual file to a contiguous byte range in
/// a source file stored in a zff object.
#[derive(Debug,Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct VirtualFileExtent {
    /// The appropriate source object of the underlying data
    pub source_object_number: u64,
    /// The appropriate source file number of the underlying data
    pub source_filenumber: u64,
    /// The appropriate source offset at which the data section starts and from which it should be read.
    pub source_offset: u64,
    /// The length of this data section (**must** always be >=1 - obviously :D).
    pub length: u64,
}

impl VirtualFileExtent {
	/// Creates a new [`VirtualFileExtent`] describing one source-backed extent of
	/// a virtual file.
	pub fn new(source_object_number: u64, source_filenumber: u64, source_offset: u64, length: u64) -> Self {
		Self {
			source_object_number,
			source_filenumber,
			source_offset,
			length,
		}
	}
}

impl ValueEncoder for VirtualFileExtent {
	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_VLFE	
	}

	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = vec![];
		vec.extend_from_slice(&self.source_object_number.encode_directly());
		vec.extend_from_slice(&self.source_filenumber.encode_directly());
		vec.extend_from_slice(&self.source_offset.encode_directly());
		vec.extend_from_slice(&self.length.encode_directly());
		vec
	}

	fn encoded_size(&self) -> usize {
		self.source_object_number.encoded_size()
			+ self.source_filenumber.encoded_size()
			+ self.source_offset.encoded_size()
			+ self.length.encoded_size()
	}
}

impl ValueDecoder for VirtualFileExtent {
	type Item = Self;

	fn decode_directly<R: Read>(data: &mut R) -> Result<Self::Item> {
		let source_object_number = u64::decode_directly(data)?;
		let source_filenumber = u64::decode_directly(data)?;
		let source_offset = u64::decode_directly(data)?;
		let length = u64::decode_directly(data)?;
		Ok(Self::new(source_object_number, source_filenumber, source_offset, length))
	}
}
