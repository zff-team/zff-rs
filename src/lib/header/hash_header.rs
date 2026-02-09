// - Parent
use super::*;

/// Header for the hash values of the dumped data stream.
/// This header is part of various footers and contains 0 or more hash values of the dumped data.\
#[derive(Debug,Clone,Eq,PartialEq)]
pub struct HashHeader {
	/// The hash values of the dumped data.
	pub hashes: Vec<HashValue>,
}

#[cfg(feature = "serde")]
impl Serialize for HashHeader {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct(Self::struct_name(), 3)?;
        state.serialize_field("version", &Self::version())?;
        let mut hashes = HashMap::new();
        for hashvalue in &self.hashes {
        	hashes.insert(hashvalue.hash_type.to_string(), hashvalue);
        }
        state.serialize_field("hash", &hashes)?;
        state.end()
    }
}

impl HashHeader {
	/// creates a new HashHeader by given values/hashes.
	pub fn new(hashes: Vec<HashValue>) -> HashHeader {
		Self {
			hashes,
		}
	}
}

impl HeaderCoding for HashHeader {
	type Item = HashHeader;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_HASH_HEADER
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_HASH_HEADER
	}

	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut Self::version().encode_directly());
		vec.append(&mut self.hashes.encode_directly());

		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<HashHeader> {
		let mut cursor = Cursor::new(data);
		Self::check_version(&mut cursor)?;
		let hashes = Vec::<HashValue>::decode_directly(&mut cursor)?;
		Ok(HashHeader::new(hashes))
	}

	fn struct_name() -> &'static str {
		"HashHeader"
	}
}

// - implement fmt::Display
impl fmt::Display for HashHeader {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", Self::struct_name())
	}
}

/// This is a part of the [HashHeader].
/// The HashValue-struct contains the appropriate hash algorithm and the hash. This struct has a version also.
#[derive(Debug,Clone,PartialEq,Eq)]
pub struct HashValue {
	/// The hash algorithm.
	pub hash_type: HashType,
	/// The hash value.
	pub hash: Vec<u8>,
	/// The ed25519 signature.
	pub ed25519_signature: Option<[u8; SIGNATURE_LENGTH]>,
}

impl HashValue {
	/// creates a new [HashValue] with the given parameters.
	pub fn new(hash_type: HashType, hash: Vec<u8>, ed25519_signature: Option<[u8; SIGNATURE_LENGTH]>,) -> HashValue{
		Self {
			hash_type,
			hash,
			ed25519_signature,
		}
	}
	/// creates a new, empty [HashValue] for a given hashtype.
	pub fn new_empty(hash_type: HashType) -> HashValue {
		let hash_default_len = hash_type.default_len();
		Self {
			hash_type,
			hash: vec!(0u8; hash_default_len/8),
			ed25519_signature: None
		}
	}

	/// returns the type of hash as [HashType](crate::hashing::HashType).
	pub fn hash_type(&self) -> &HashType {
		&self.hash_type
	}

	/// sets the hash value.
	pub fn set_hash(&mut self, hash: Vec<u8>) {
		self.hash = hash
	}

	/// returns the underlying hash value
	pub fn hash(&self) -> &Vec<u8> {
		&self.hash
	}

	/// sets the appropriate ed25519 signature
	pub fn set_ed25519_signature(&mut self, signature: [u8; SIGNATURE_LENGTH]) {
		self.ed25519_signature = Some(signature)
	}

	/// returns the appropriate signature
	pub fn ed25519_signature(&self) -> Option<[u8; SIGNATURE_LENGTH]> {
		self.ed25519_signature
	}
}


impl HeaderCoding for HashValue {
	type Item = HashValue;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_HASH_VALUE
	}

	fn version() -> u8 {
		DEFAULT_HEADER_VERSION_HASH_VALUE_HEADER
	}
	
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut Self::version().encode_directly());
		vec.push(self.hash_type.clone() as u8);
		vec.append(&mut self.hash.encode_directly());
		match self.ed25519_signature {
			None => (),
			Some(signature) => vec.append(&mut signature.encode_directly()),
		};
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<HashValue> {
		let mut cursor = Cursor::new(&data);
		Self::check_version(&mut cursor)?;
		let hash_type = match u8::decode_directly(&mut cursor)? {
			0 => HashType::Blake2b512,
			1 => HashType::SHA256,
			2 => HashType::SHA512,
			3 => HashType::SHA3_256,
			4 => HashType::Blake3,
			_ => return Err(ZffError::new(ZffErrorKind::Invalid, ERROR_HEADER_DECODER_UNKNOWN_HASH_TYPE)),
		};
	 	let hash = Vec::<u8>::decode_directly(&mut cursor)?;
	 	
	 	let mut ed25519_signature = None;
		if cursor.position() < (data.len() as u64 - 1) {
			let mut buffer = [0; SIGNATURE_LENGTH];
			cursor.read_exact(&mut buffer)?;
			ed25519_signature = Some(buffer);
		}

		Ok(HashValue::new(hash_type, hash, ed25519_signature))
	}

	fn struct_name() -> &'static str {
		"HashValue"
	}
}

// - implement fmt::Display
impl fmt::Display for HashValue {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", Self::struct_name())
	}
}

#[cfg(feature = "serde")]
impl Serialize for HashValue {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct(Self::struct_name(), 3)?;
        state.serialize_field("hash_type", &self.hash_type.to_string())?;
        state.serialize_field("hash", &hex::encode(&self.hash))?;
        if let Some(signature) = &self.ed25519_signature {
        	state.serialize_field("ed25519_signature", &base64engine.encode(signature))?;
        }
        state.end()
    }
}