// - STD
use std::io::{Cursor, Read};

// - internal
use crate::{
	Result,
	HeaderEncoder,
	HeaderDecoder,
	ValueEncoder,
	ValueDecoder,
	HeaderObject,
	header::{
		CompressionHeader,
		DescriptionHeader,
		EncryptionHeader,
		HashHeader,
	},
	ZffError,
	ZffErrorKind,
	Encryption,
	DEFAULT_LENGTH_HEADER_IDENTIFIER,
	DEFAULT_LENGTH_VALUE_HEADER_LENGTH,
	HEADER_IDENTIFIER_MAIN_HEADER,
	HEADER_IDENTIFIER_ENCRYPTED_MAIN_HEADER,
	ERROR_HEADER_DECODER_MAIN_HEADER_ENCRYPTED,
	ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER,
	ERROR_HEADER_DECODER_MAIN_HEADER_NOT_ENCRYPTED,
};

// - external
use serde::ser::{Serialize, Serializer, SerializeStruct};

/// The main header is the first Header, which can be found at the beginning of the first segment.\
/// This header contains a lot of other headers (e.g. compression header, description header, ...) and start information.
#[derive(Debug,Clone)]
pub struct MainHeader {
	header_version: u8,
	encryption_header: Option<EncryptionHeader>,
	compression_header: CompressionHeader,
	description_header: DescriptionHeader,
	hash_header: HashHeader,
	chunk_size: u8,
	signature_flag: u8,
	segment_size: u64,
	unique_identifier: i64,
	length_of_data: u64,
}

impl MainHeader {
	/// returns a new main header with the given values.
	pub fn new(
		header_version: u8,
		encryption_header: Option<EncryptionHeader>,
		compression_header: CompressionHeader,
		description_header: DescriptionHeader,
		hash_header: HashHeader,
		chunk_size: u8,
		signature_flag: u8,
		segment_size: u64,
		unique_identifier: i64,
		length_of_data: u64) -> MainHeader {
		Self {
			header_version: header_version,
			encryption_header: encryption_header,
			compression_header: compression_header,
			description_header: description_header,
			hash_header: hash_header,
			chunk_size: chunk_size,
			signature_flag: signature_flag,
			segment_size: segment_size,
			unique_identifier: unique_identifier,
			length_of_data: length_of_data,
		}
	}

	fn encode_encrypted_header<K>(&self, key: K) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>
	{
		let mut vec = Vec::new();
		vec.push(self.header_version);
		let encryption_header = match &self.encryption_header {
			None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionHeader, "")),
			Some(header) => {
				header
			}
		};
		let encryption_flag: u8 = 2;
		vec.push(encryption_flag);
		vec.append(&mut encryption_header.encode_directly());

		let mut data_to_encrypt = Vec::new();
		data_to_encrypt.append(&mut self.encode_content());

		let mut encrypted_data = Encryption::encrypt_header(
			key, data_to_encrypt,
			encryption_header.nonce(),
			encryption_header.algorithm()
			)?;

		vec.append(&mut encrypted_data);
		return Ok(vec);
	}

	/// decodes the encrypted main header with the given password
	pub fn decode_encrypted_header_with_password<R, P>(data: &mut R, password: P) -> Result<MainHeader>
	where
		R: Read,
		P: AsRef<[u8]>,
	{
		if !Self::check_identifier(data) {
			return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER));
		};
		let header_length = Self::decode_header_length(data)? as usize;
		let header_content = vec![0u8; header_length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
		let mut cursor = Cursor::new(header_content);
		let header_version = u8::decode_directly(&mut cursor)?;
		let encryption_flag = u8::decode_directly(&mut cursor)?;
		if encryption_flag != 2 {
			return Err(ZffError::new(ZffErrorKind::HeaderDecodeEncryptedMainHeader, ERROR_HEADER_DECODER_MAIN_HEADER_NOT_ENCRYPTED));
		}
		let encryption_header = EncryptionHeader::decode_directly(&mut cursor)?;
		let encryted_data = Vec::<u8>::decode_directly(&mut cursor)?;		
		let encryption_key = encryption_header.decrypt_encryption_key(password)?;
		let nonce = encryption_header.nonce();
		let algorithm = encryption_header.algorithm();
		let decrypted_data = Encryption::decrypt_header(encryption_key, encryted_data, nonce, algorithm)?;
		let mut cursor = Cursor::new(decrypted_data);
		let (compression_header,
			description_header,
			hash_header,
			chunk_size,
			signature_flag,
			segment_size,
			unique_identifier,
			length_of_data) = Self::decode_inner_content(&mut cursor)?;
		let main_header = Self::new(
			header_version,
			Some(encryption_header),
			compression_header,
			description_header,
			hash_header,
			chunk_size,
			signature_flag,
			segment_size,
			unique_identifier,
			length_of_data);
		Ok(main_header)
	}

	/// encodes the main header to a ```Vec<u8>```. The encryption flag will be set to 2.
	/// # Error
	/// The method returns an error, if the encryption header is missing (=None).
	pub fn encode_encrypted_header_directly<K>(&self, key: K) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
	{
		let mut vec = Vec::new();
		let mut encoded_header = self.encode_encrypted_header(key)?;
		let identifier = HEADER_IDENTIFIER_ENCRYPTED_MAIN_HEADER;
		let encoded_header_length = 4 + 8 + (encoded_header.len() as u64); //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.append(&mut encoded_header);

		Ok(vec)
	}

	fn encode_content(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		
		vec.append(&mut self.compression_header.encode_directly());
		vec.append(&mut self.description_header.encode_directly());
		vec.append(&mut self.hash_header.encode_directly());
		vec.push(self.chunk_size);
		vec.push(self.signature_flag);
		vec.append(&mut self.segment_size.encode_directly());
		vec.append(&mut self.unique_identifier.encode_directly());
		vec.append(&mut self.length_of_data.encode_directly());

		vec
	}

	fn decode_inner_content<R: Read>(inner_content: &mut R) -> Result<(
		CompressionHeader,
		DescriptionHeader,
		HashHeader,
		u8, // chunk size
		u8, // signature flag
		u64, // segment size
		i64, // unique identifier
		u64, // length of data
		)>{
		let compression_header = CompressionHeader::decode_directly(inner_content)?;
		let description_header = DescriptionHeader::decode_directly(inner_content)?;
		let hash_header = HashHeader::decode_directly(inner_content)?;
		let chunk_size = u8::decode_directly(inner_content)?;
		let signature_flag = u8::decode_directly(inner_content)?;
		let segment_size = u64::decode_directly(inner_content)?;
		let unique_identifier = i64::decode_directly(inner_content)?;
		let length_of_data = u64::decode_directly(inner_content)?;
		let inner_content = (
			compression_header,
			description_header,
			hash_header,
			chunk_size,
			signature_flag,
			segment_size,
			unique_identifier,
			length_of_data);
		Ok(inner_content)
	}

	/// sets the length of the dumped data.
	pub fn set_length_of_data(&mut self, len: u64) {
		self.length_of_data = len;
	}

	/// sets the hash header.
	pub fn set_hash_header(&mut self, hash_header: HashHeader) {
		self.hash_header = hash_header;
	}

	/// returns the header version.
	pub fn header_version(&self) -> u8 {
		self.header_version
	}

	/// returns the chunk_size.
	pub fn chunk_size(&self) -> usize {
		1<<self.chunk_size
	}

	/// returns the segment size
	pub fn segment_size(&self) -> u64 {
		self.segment_size.clone()
	}

	/// returns the len() of the ```Vec<u8>``` (encoded main header).
	pub fn get_encoded_size(&self) -> usize {
		self.encode_directly().len()
	}

	/// returns the len() of the ```Vec<u8>``` (encoded encrypted main header).
	/// # Error
	/// The method fails, if the encryption fails or no encryption header is present.
	pub fn get_encrypted_encoded_size<K>(&self, key: K) -> Result<usize>
	where
		K: AsRef<[u8]>,
	{
		Ok(self.encode_encrypted_header_directly(key)?.len())
	}

	/// returns, if the chunks has a ed25519 signature or not.
	pub fn has_signature(&self) -> bool {
		self.signature_flag != 0
	}

	/// sets the acquisition end timestamp of the inner description header.
	pub fn set_acquisition_end(&mut self, timestamp: u64) {
		self.description_header.set_acquisition_end(timestamp);
	}

	/// returns a reference to the inner compression header
	pub fn compression_header(&self) -> &CompressionHeader {
		&self.compression_header
	}

	/// returns a reference to the inner encryption header (if available)
	pub fn encryption_header(&self) -> &Option<EncryptionHeader> {
		&self.encryption_header
	}

	/// returns a reference to the inner hash header 
	pub fn hash_header(&self) -> &HashHeader {
		&self.hash_header
	}

	/// returns the length of the content data
	pub fn length_of_data(&self) -> u64 {
		self.length_of_data
	}

	/// returns the unique identifier
	pub fn unique_identifier(&self) -> i64 {
		self.unique_identifier
	}
}

impl HeaderObject for MainHeader {
	fn identifier() -> u32 {
		HEADER_IDENTIFIER_MAIN_HEADER
	}
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.push(self.header_version);
		match &self.encryption_header {
			None => {
				let encryption_flag: u8 = 0;
				vec.push(encryption_flag);
			},
			Some(header) => {
				let encryption_flag: u8 = 1;
				vec.push(encryption_flag);
				vec.append(&mut header.encode_directly());
			},
		};

		vec.append(&mut self.encode_content());

		vec
	}
}

impl HeaderEncoder for MainHeader {}

impl HeaderDecoder for MainHeader {
	type Item = MainHeader;

	fn decode_content(data: Vec<u8>) -> Result<MainHeader> {
		let mut cursor = Cursor::new(data);
		let header_version = u8::decode_directly(&mut cursor)?;
		//encryption flag:
		let mut encryption_header = None;
		let encryption_flag = u8::decode_directly(&mut cursor)?;
		if encryption_flag == 1 {
			encryption_header = Some(EncryptionHeader::decode_directly(&mut cursor)?);
		} else if encryption_flag > 1 {
			return Err(ZffError::new(ZffErrorKind::HeaderDecodeEncryptedMainHeader, ERROR_HEADER_DECODER_MAIN_HEADER_ENCRYPTED))
		}
		let (compression_header,
			description_header,
			hash_header,
			chunk_size,
			signature_flag,
			segment_size,
			unique_identifier,
			length_of_data) = Self::decode_inner_content(&mut cursor)?;
		let main_header = Self::new(
			header_version,
			encryption_header,
			compression_header,
			description_header,
			hash_header,
			chunk_size,
			signature_flag,
			segment_size,
			unique_identifier,
			length_of_data);
		Ok(main_header)
	}
}

impl Serialize for MainHeader {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("MainHeader", 10)?;
        state.serialize_field("header_version", &self.header_version)?;
        state.serialize_field("encryption", &self.encryption_header)?;
        state.serialize_field("compression", &self.compression_header)?;

        state.serialize_field("description", &self.description_header)?;
        state.serialize_field("hashing", &self.hash_header)?;
        state.serialize_field("chunk_size", &self.chunk_size)?;

        state.serialize_field("signature_flag", &(self.signature_flag != 0))?;
        state.serialize_field("segment_size", &self.segment_size.to_string())?;
        state.serialize_field("unique identifier", &self.unique_identifier)?;

        state.serialize_field("length_of_data", &self.length_of_data.to_string())?;
        state.end()
    }
}