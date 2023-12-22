// - STD
use core::borrow::Borrow;
use std::io::{Cursor, Read};
use std::fmt;

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueDecoder,
	ValueEncoder,
	Encryption,
	ZffError,
	ZffErrorKind,
	FOOTER_IDENTIFIER_FILE_FOOTER,
	DEFAULT_LENGTH_HEADER_IDENTIFIER,
	DEFAULT_LENGTH_VALUE_HEADER_LENGTH,
	DEFAULT_FOOTER_VERSION_FILE_FOOTER,
	ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER,
};
use crate::header::{
	HashHeader,
	EncryptionInformation,
};

// - external
#[cfg(feature = "serde")]
use serde::Serialize;


/// The file footer is written at the end of each acquired file.
/// The file footer contains several metadata about the acquisition process itself: e.g. the acquisition start/end time of the appropriate file,
/// hash values, or size information.
/// The general structure of the file footer is the same for all file types.
#[derive(Debug,Clone,Eq,PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct FileFooter {
	/// the appropriate file number.
	pub file_number: u64,
	/// the acquisition start time for this file.
	pub acquisition_start: u64,
	/// the acquisition end/finish time for this file.
	pub acquisition_end: u64,
	/// The appropriate hash header for this file.
	pub hash_header: HashHeader,
	/// the first chunk number which was used for this file.
	pub first_chunk_number: u64,
	/// The full number of chunks for this file.
	pub number_of_chunks: u64,
	/// the original (uncompressed & unencrypted) length of the file.  
	/// - If the file is a regular file, this method returns the original (uncompressed, unencrypted) size
	/// of the file (without "filesystem-"metadata - just the size of the file content).  
	/// - If the file is a hardlink, this method returns the size of the inner value (just the size of the appropriate filenumber: 8).  
	/// - If the file is a directory, this method returns the size of the underlying vector of children.  
	/// - If the file is a symlink, this method returns the length of the linked path.  
	pub length_of_data: u64,
}

impl FileFooter {
	/// creates a new FileFooter by given values/hashes.
	pub fn new(
		file_number: u64,
		acquisition_start: u64, 
		acquisition_end: u64, 
		hash_header: HashHeader, 
		first_chunk_number: u64, 
		number_of_chunks: u64, 
		length_of_data: u64) -> FileFooter {
		Self {
			file_number,
			acquisition_start,
			acquisition_end,
			hash_header,
			first_chunk_number,
			number_of_chunks,
			length_of_data,
		}
	}

	fn encode_content(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.acquisition_start.encode_directly());
		vec.append(&mut self.acquisition_end.encode_directly());
		vec.append(&mut self.hash_header.encode_directly());
		vec.append(&mut self.first_chunk_number.encode_directly());
		vec.append(&mut self.number_of_chunks.encode_directly());
		vec.append(&mut self.length_of_data.encode_directly());
		vec
	}

	/// encrypts the file footer by the given encryption information and returns the encrypted file footer.
	pub fn encrypt_directly<E>(&self, encryption_information: E) -> Result<Vec<u8>>
	where
		E: Borrow<EncryptionInformation>
	{
		let mut vec = Vec::new();
		let mut encrypted_content = Encryption::encrypt_file_footer(
			&encryption_information.borrow().encryption_key, 
			self.encode_content(), 
			self.file_number, 
			&encryption_information.borrow().algorithm)?;
		let identifier = Self::identifier();
		let encoded_header_length = (DEFAULT_LENGTH_HEADER_IDENTIFIER + DEFAULT_LENGTH_VALUE_HEADER_LENGTH + encrypted_content.len()) as u64; //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.append(&mut encrypted_content);

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
			return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER));
		};
		let header_length = Self::decode_header_length(data)? as usize;
		let mut header_content = vec![0u8; header_length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
		data.read_exact(&mut header_content)?;
		let mut cursor = Cursor::new(header_content);
		Self::check_version(&mut cursor)?;
		let file_number = u64::decode_directly(&mut cursor)?;
		
		let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
		let algorithm = &encryption_information.borrow().algorithm;
		let decrypted_data = Encryption::decrypt_file_footer(
			&encryption_information.borrow().encryption_key, 
			encrypted_data, 
			file_number, 
			algorithm)?;
		let mut cursor = Cursor::new(decrypted_data);
		let (acquisition_start, acquisition_end, hash_header, first_chunk_number, number_of_chunks, length_of_data) = Self::decode_inner_content(&mut cursor)?;
		Ok(FileFooter::new(file_number, acquisition_start, acquisition_end, hash_header, first_chunk_number, number_of_chunks, length_of_data))
	}

	#[allow(clippy::type_complexity)]
	fn decode_inner_content<R: Read>(inner_content: &mut R) -> Result<(
		u64, //acquisition_start
		u64, //acquisition_end
		HashHeader, //HashHeader
		u64, //first_chunk_number
		u64, // number_of_chunks,
		u64, // length_of_data
		)> {
		let acquisition_start = u64::decode_directly(inner_content)?;
		let acquisition_end = u64::decode_directly(inner_content)?;
		let hash_header = HashHeader::decode_directly(inner_content)?;
		let first_chunk_number = u64::decode_directly(inner_content)?;
		let number_of_chunks = u64::decode_directly(inner_content)?;
		let length_of_data = u64::decode_directly(inner_content)?;

		let inner_content = (
			acquisition_start,
			acquisition_end,
			hash_header,
			first_chunk_number,
			number_of_chunks,
			length_of_data);
		Ok(inner_content)
	}
}

impl HeaderCoding for FileFooter {
	type Item = FileFooter;
	fn version() -> u8 { 
		DEFAULT_FOOTER_VERSION_FILE_FOOTER
	}
	fn identifier() -> u32 {
		FOOTER_IDENTIFIER_FILE_FOOTER
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = vec![Self::version()];
		vec.append(&mut self.file_number.encode_directly());
		vec.append(&mut self.encode_content());
		vec
	}
	fn decode_content(data: Vec<u8>) -> Result<FileFooter> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?;
		let file_number = u64::decode_directly(&mut cursor)?;
		let (acquisition_start, acquisition_end, hash_header, first_chunk_number, number_of_chunks, length_of_data) = Self::decode_inner_content(&mut cursor)?;
		Ok(FileFooter::new(file_number, acquisition_start, acquisition_end, hash_header, first_chunk_number, number_of_chunks, length_of_data))
	}
}

// - implement fmt::Display
impl fmt::Display for FileFooter {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.struct_name())
	}
}

// - this is a necassary helper method for fmt::Display and serde::ser::SerializeStruct.
impl FileFooter {
	fn struct_name(&self) -> &'static str {
		"FileFooter"
	}
}