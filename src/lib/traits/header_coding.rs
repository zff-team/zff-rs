// - Parent
use super::*;

/// The ```HeaderCoding``` trait specifies an interface for the common header methods and the encoding and decoding methods.
pub trait HeaderCoding {
	/// the return value for decode_content(), decode_directly(), decode_for_key();
	type Item;

	/// returns the identifier (=Magic bytes) of the header.
	fn identifier() -> u32;
	/// encodes the header.
	fn encode_header(&self) -> Vec<u8>;

	/// returns the size of the encoded header (in bytes)
	fn header_size(&self) -> usize {
		self.encode_directly().len()
	}

	/// returns the version of the header.
	/// This reflects the default version of the appropiate header used in zff v3.
	fn version() -> u8;

	/// encodes a given key.
	fn encode_key<K: Into<String>>(key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let key = key.into();
		let key_length = key.len() as u8;
		vec.push(key_length);
		vec.append(&mut key.into_bytes());
		vec
	}
	/// encodes the (header) value/object directly (= without key).
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_header = self.encode_header();
		let identifier = Self::identifier();
		let encoded_header_length = (DEFAULT_LENGTH_HEADER_IDENTIFIER + DEFAULT_LENGTH_VALUE_HEADER_LENGTH + encoded_header.len()) as u64; //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.append(&mut encoded_header);

		vec
	}

	/// decodes the length of the header.
	fn decode_header_length<R: Read>(data: &mut R) -> Result<u64> {
		match data.read_u64::<LittleEndian>() {
			Ok(value) => Ok(value),
			Err(_) => Err(ZffError::new(ZffErrorKind::EncodingError, ERROR_HEADER_DECODER_HEADER_LENGTH)),
		}
	}

	/// checks if the read identifier is valid for this header.
	fn check_identifier<R: Read>(data: &mut R) -> bool {
		let identifier = match data.read_u32::<BigEndian>() {
			Ok(val) => val,
			Err(_) => return false,
		};
		#[cfg(feature = "log")]
		log::trace!("Read identifier: {:x}", identifier);
		identifier == Self::identifier()
	}

	/// checks if the read header / footer version is supported by this crate (only zff v3 headers / footers are supported).
	fn check_version<R: Read>(data: &mut R) -> Result<()> {
		let version = match data.read_u8() {
			Ok(val) => val,
			Err(_) => return Err(ZffError::new(ZffErrorKind::EncodingError, ERROR_HEADER_DECODER_HEADER_LENGTH)),
		};
		if version != Self::version() {
			return Err(ZffError::new(ZffErrorKind::Unsupported, format!("{ERROR_UNSUPPORTED_VERSION}{version}")));
		}
		Ok(())
	}

	/// decodes the content of the header.
	fn decode_content(data: Vec<u8>) -> Result<Self::Item>;
	
	/// decodes the header directly.
	fn decode_directly<R: Read>(data: &mut R) -> Result<Self::Item> {
		#[cfg(feature = "log")]
    	trace!("Trying to decode a {}", Self::struct_name());

		if !Self::check_identifier(data) {
			return Err(ZffError::new(ZffErrorKind::Invalid, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER));
		}
		let header_length = Self::decode_header_length(data)? as usize;
		let mut header_content = vec![0u8; header_length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
		data.read_exact(&mut header_content)?;
		Self::decode_content(header_content)
	}

	/// Method to show the "name" of the appropriate struct (e.g. to use this with fmt::Display).
	/// This method is a necassary helper method for fmt::Display and serde::ser::SerializeStruct (and for some debugging purposes).
	fn struct_name() -> &'static str;
}