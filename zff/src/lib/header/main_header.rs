// - internal
use crate::{
	Result,
	HeaderEncoder,
	HeaderObject,
	CompressionHeader,
	DescriptionHeader,
	EncryptionHeader,
	HashHeader,
	SegmentHeader,
	ZffError,
	ZffErrorKind,
	Encryption,
	HEADER_IDENTIFIER_MAIN_HEADER,
	HEADER_IDENTIFIER_ENCRYPTED_MAIN_HEADER,
};

#[derive(Debug,Clone)]
pub struct MainHeader {
	header_version: u8,
	encryption_header: Option<EncryptionHeader>,
	compression_header: CompressionHeader,
	description_header: DescriptionHeader,
	hash_header: HashHeader,
	chunk_size: u8,
	signature_flag: u8,
	segment_size_in_bytes: u64,
	segment_header: SegmentHeader,
	length_of_data: u64,
}

impl MainHeader {
	pub fn new(
		header_version: u8,
		encryption_header: Option<EncryptionHeader>,
		compression_header: CompressionHeader,
		description_header: DescriptionHeader,
		hash_header: HashHeader,
		chunk_size: u8,
		signature_flag: u8,
		segment_size_in_bytes: u64,
		segment_header: SegmentHeader,
		length_of_data: u64) -> MainHeader {
		Self {
			header_version: header_version,
			encryption_header: encryption_header,
			compression_header: compression_header,
			description_header: description_header,
			hash_header: hash_header,
			chunk_size: chunk_size,
			signature_flag: signature_flag,
			segment_size_in_bytes: segment_size_in_bytes,
			segment_header: segment_header,
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
		let encryption_flag: u8 = 1;
		vec.push(encryption_flag);
		vec.append(&mut encryption_header.encode_directly());

		let mut data_to_encrypt = Vec::new();
		data_to_encrypt.append(&mut self.encode_content());

		let mut encrypted_data = Encryption::encrypt_header(
			key, data_to_encrypt,
			encryption_header.encryption_key_nonce(),
			encryption_header.encryption_algorithm()
			)?;

		vec.append(&mut encrypted_data);
		return Ok(vec);
	}

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

	pub fn new_from_encrypted_header(
		_header_version: u8,
		_encryption_header: EncryptionHeader,
		_encrypted_data: Vec<u8>,
		) -> Result<MainHeader> {
		unimplemented!()
	}

	pub fn encode_content(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		
		vec.append(&mut self.compression_header.encode_directly());
		vec.append(&mut self.description_header.encode_directly());
		vec.append(&mut self.hash_header.encode_directly());
		vec.push(self.chunk_size);
		vec.push(self.signature_flag);
		vec.append(&mut self.segment_size_in_bytes.encode_directly());
		vec.append(&mut self.segment_header.encode_directly());
		vec.append(&mut self.length_of_data.encode_directly());

		vec
	}

	pub fn set_length_of_data(&mut self, len: u64) {
		self.length_of_data = len;
	}

	pub fn set_segment_header(&mut self, segment_header: SegmentHeader) {
		self.segment_header = segment_header
	}

	pub fn set_hash_header(&mut self, hash_header: HashHeader) {
		self.hash_header = hash_header
	}

	pub fn header_version(&self) -> u8 {
		self.header_version
	}

	pub fn chunk_size(&self) -> usize {
		1<<self.chunk_size
	}

	pub fn segment_size(&self) -> u64 {
		self.segment_size_in_bytes.clone()
	}

	pub fn get_encoded_size(&self) -> usize {
		self.encode_directly().len()
	}

	pub fn has_signature(&self) -> bool {
		self.signature_flag != 0
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

impl HeaderEncoder for MainHeader {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_header = self.encode_header();
		let identifier = Self::identifier();
		let encoded_header_length = 4 + 8 + (encoded_header.len() as u64); //4 bytes identifier + 8 bytes for length + length itself
		vec.append(&mut identifier.to_be_bytes().to_vec());
		vec.append(&mut encoded_header_length.to_le_bytes().to_vec());
		vec.append(&mut encoded_header);

		vec
	}
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = Self::encode_key(key);
		vec.append(&mut encoded_key);
		vec.append(&mut self.encode_directly());
		vec
	}
}