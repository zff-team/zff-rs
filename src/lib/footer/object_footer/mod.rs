// - STD
use core::borrow::Borrow;
use std::io::{Cursor, Read};
use std::collections::HashMap;
use std::fmt;

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
	FOOTER_IDENTIFIER_OBJECT_FOOTER_VIRTUAL,
	DEFAULT_LENGTH_VALUE_HEADER_LENGTH,
	DEFAULT_LENGTH_HEADER_IDENTIFIER,
	DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_VIRTUAL,
	ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER,
	ERROR_HEADER_DECODER_HEADER_LENGTH,
};
use crate::header::{
	HashHeader,
	EncryptionInformation,
};

// - modules
mod object_footer_physical;
mod object_footer_logical;
mod object_footer_virtual;

// - re-exports
pub use object_footer_physical::*;
pub use object_footer_logical::*;
pub use object_footer_virtual::*;

// - external
use byteorder::{LittleEndian, BigEndian, ReadBytesExt};
#[cfg(feature = "serde")]
use serde::{
	Deserialize,
	Serialize,
};


/// Each object contains its own object footer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum ObjectFooter {
	/// A physical object contains a [ObjectFooterPhysical].
	Physical(ObjectFooterPhysical),
	/// A logical object contains a [ObjectFooterLogical].
	Logical(ObjectFooterLogical),
	/// Footer of a virtual object.
	Virtual(ObjectFooterVirtual),
}

impl ObjectFooter {
	/// returns the version of the object footer.
	pub fn version(&self) -> u8 {
		match self {
			ObjectFooter::Physical(_) => ObjectFooterPhysical::version(),
			ObjectFooter::Logical(_) => ObjectFooterLogical::version(),
			ObjectFooter::Virtual(_) => ObjectFooterVirtual::version(),
		}
	}

	/// checks if the identifier matches to an physical or logical object footer. 
	/// Returns 1 for a physical object footer, 2 for a logical object footer and 0 if neither applies.
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

	/// Returns the appropriate object number.
	pub fn object_number(&self) -> u64 {
		match self {
			ObjectFooter::Physical(footer) => footer.object_number,
			ObjectFooter::Logical(footer) => footer.object_number,
			ObjectFooter::Virtual(footer) => footer.object_number,
		}
	}

	/// Returns the appropriate acquisition start timestamp.
	pub fn acquisition_start(&self) -> u64 {
		match self {
			ObjectFooter::Physical(footer) => footer.acquisition_start,
			ObjectFooter::Logical(footer) => footer.acquisition_start,
			ObjectFooter::Virtual(footer) => footer.creation_timestamp,
		}
	}

	/// Returns the appropriate acquisition end timestamp.
	pub fn acquisition_end(&self) -> u64 {
		match self {
			ObjectFooter::Physical(footer) => footer.acquisition_end,
			ObjectFooter::Logical(footer) => footer.acquisition_end,
			ObjectFooter::Virtual(footer) => footer.creation_timestamp,
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

// - implement fmt::Display
impl fmt::Display for ObjectFooter {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", Self::struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl ObjectFooter {
	fn struct_name() -> &'static str {
		"ObjectFooter"
	}
}

impl Encryption for ObjectFooter {
	fn crypto_nonce_padding() -> u8 {
		0b00100000
	}
}


/// Each object contains its own object footer (and this is the encrypted variant).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", derive(Deserialize))]
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
			EncryptedObjectFooter::Physical(_) => ObjectFooterPhysical::version(),
			EncryptedObjectFooter::Logical(_) => ObjectFooterLogical::version(),
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
		self.decrypt(key, algorithm)
	}
}