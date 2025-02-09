// - internal
use super::*;

/// An [ObjectFooterVirtual] is written at the end of an virtual object.
/// This footer contains various information about the acquisition process:
/// - the acquisition start time
/// - the acquisition start time
/// - the size of the (uncompressed and unencrypted) underlying data
/// - the first chunk number, which is used for this physical dump
/// - the total number of chunks, used for this physical dump
/// - a hash header with the appropriate hash values of the underlying physical dump
#[derive(Debug,Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ObjectFooterVirtual {
	/// The object number of the footer.
	pub object_number: u64,
	/// UNIX timestamp when the creation of this objects has started.
	pub creation_timestamp: u64,
	/// A list of all objects which are affected by this virtual object.
	pub passive_objects: Vec<u64>,
	/// The length of the original data in bytes.
	pub length_of_data: u64,
	/// The map of to the highest layer.
	pub virtual_object_map_offset: u64,
	/// The map of the segments to the appropriate next layer
	pub virtual_object_map_segment_no: u64,
}

impl ObjectFooterVirtual {
	/// creates a new [ObjectFooterVirtual] with the given values.
	pub fn with_data(object_number: u64, 
		creation_timestamp: u64, 
		passive_objects: Vec<u64>,
		length_of_data: u64,
		virtual_object_map_offset: u64,
		virtual_object_map_segment_no: u64) -> Self {
		Self {
			object_number,
			creation_timestamp,
			passive_objects,
			length_of_data,
			virtual_object_map_offset,
			virtual_object_map_segment_no,
		}
	}

	fn encode_content(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.creation_timestamp.encode_directly());
		vec.append(&mut self.passive_objects.encode_directly());
		vec.append(&mut self.length_of_data.encode_directly());
		vec.append(&mut self.virtual_object_map_offset.encode_directly());
		vec.append(&mut self.virtual_object_map_segment_no.encode_directly());
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
	fn decode_inner_content<R: Read>(data: &mut R) -> Result<(
		u64, //creation_timestamp
		Vec<u64>, //passive_objects
		u64, //length_of_data
		u64, //virtual_object_map_offset
		u64, //virtual_object_map_segment_no,
		)> {
		let creation_timestamp = u64::decode_directly(data)?;
		let passive_objects = Vec::<u64>::decode_directly(data)?;
		let length_of_data = u64::decode_directly(data)?;
		let virtual_object_map_offset = u64::decode_directly(data)?;
		let virtual_object_map_segment_no = u64::decode_directly(data)?;
		Ok((
			creation_timestamp,
			passive_objects,
			length_of_data,
			virtual_object_map_offset,
			virtual_object_map_segment_no,
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
	type Item = ObjectFooterVirtual;
	fn version() -> u8 { 
		DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_VIRTUAL
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_OBJECT_FOOTER_VIRTUAL
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
			length_of_data,
			virtual_object_map_offset,
			virtual_object_map_segment_no) = Self::decode_inner_content(&mut cursor)?;
		Ok(Self::with_data(
			object_number,
			creation_timestamp, 
			passive_objects,
			length_of_data,
			virtual_object_map_offset,
			virtual_object_map_segment_no))
	}

	fn struct_name() -> &'static str {
		"ObjectFooterVirtual"
	}
}

/// Represents an encrypted object footer of a virtual object.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct EncryptedObjectFooterVirtual {
	/// The appropriate object number.
	pub object_number: u64,
	/// The underlying data in encrypted form.
	pub encrypted_data: Vec<u8>,
}

impl EncryptedObjectFooterVirtual {
	/// Creates a new [EncryptedObjectFooterPhysical] by the given values.
	pub fn with_data(object_number: u64, encrypted_data: Vec<u8>) -> Self {
		Self {
			object_number,
			encrypted_data,
		}
	}

	/// Tries to decrypt the ObjectFooter. If an error occures, the EncryptedObjectFooterVirtual is still available.
	pub fn decrypt<A, K>(&self, key: K, algorithm: A) -> Result<ObjectFooterVirtual>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		self.inner_decrypt(key, algorithm)
	}

	/// Tries to decrypt the ObjectFooter. Consumes the EncryptedObjectFooterPhysical, regardless of whether an error occurs or not.
	pub fn decrypt_and_consume<A, K>(self, key: K, algorithm: A) -> Result<ObjectFooterVirtual>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		self.inner_decrypt(key, algorithm)
	}

	fn inner_decrypt<A, K>(&self, key: K, algorithm: A) -> Result<ObjectFooterVirtual>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		let content = ObjectFooter::decrypt(
			key, &self.encrypted_data, self.object_number, algorithm.borrow())?;
		let mut cursor = Cursor::new(content);
		let (creation_timestamp, 
			passive_objects, 
			length_of_data,
			virtual_object_map_offset,
			virtual_object_map_segment_no) = ObjectFooterVirtual::decode_inner_content(&mut cursor)?;
		Ok(ObjectFooterVirtual::with_data(
			self.object_number,
			creation_timestamp,
			passive_objects,
			length_of_data,
			virtual_object_map_offset,
			virtual_object_map_segment_no))
	}
}

// - implement fmt::Display
impl fmt::Display for EncryptedObjectFooterVirtual {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", Self::struct_name())
	}
}

impl HeaderCoding for EncryptedObjectFooterVirtual {
	type Item = EncryptedObjectFooterVirtual;
	fn version() -> u8 { 
		DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_VIRTUAL
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_OBJECT_FOOTER_VIRTUAL
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
		let version = u8::decode_directly(&mut cursor)?;
		if version != DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_VIRTUAL {
			return Err(ZffError::new(ZffErrorKind::Unsupported, format!("{ERROR_UNSUPPORTED_VERSION}{version}")))
		};
		let object_number = u64::decode_directly(&mut cursor)?;
		let encryption_flag = bool::decode_directly(&mut cursor)?;
		if !encryption_flag {
			return Err(ZffError::new(
				ZffErrorKind::EncryptionError, 
				ERROR_DECODE_UNENCRYPTED_OBJECT_WITH_DECRYPTION_FN));
		}
		let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
		Ok(Self::with_data(
			object_number,
			encrypted_data))
	}

	fn struct_name() -> &'static str {
		"EncryptedObjectFooterVirtual"
	}
}