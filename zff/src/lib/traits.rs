// - STD
use std::io::{Read};

// - internal
use crate::{
	Result,
	ZffError,
	ZffErrorKind,
};
use crate::{
	DEFAULT_LENGTH_VALUE_HEADER_LENGTH,
	DEFAULT_LENGTH_HEADER_IDENTIFIER,
	ERROR_HEADER_DECODER_HEADER_LENGTH,
	ERROR_HEADER_DECODER_KEY_POSITION,
	ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER,
};

// - external
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};

/// The ```HeaderObject``` trait specifies an interface for the common header methods.
pub trait HeaderObject {
	/// returns the identifier (=Magic bytes) of the header.
	fn identifier() -> u32;
	/// encodes the header.
	fn encode_header(&self) -> Vec<u8>;
}

/// The ```HeaderObject``` trait specifies an interface for the common encoding methods.
pub trait HeaderEncoder: HeaderObject {
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
	/// encodes a key to the (header) value/object.
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = Self::encode_key(key);
		vec.append(&mut encoded_key);
		vec.append(&mut self.encode_directly());
		vec
	}
}

/// encoder methods for values (and primitive types). This is an extension trait.
pub trait ValueEncoder {
	/// encodes a given key.
	fn encode_key<K: Into<String>>(key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let key = key.into();
		let key_length = key.len() as u8;
		vec.push(key_length);
		vec.append(&mut key.into_bytes());
		vec
	}
	/// encodes the value directly (= without key).
	fn encode_directly(&self) -> Vec<u8>;
	/// encodes a key to the value.
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8>;
}

impl ValueEncoder for u8 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(*self);
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

impl ValueEncoder for u16 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_le_bytes().to_vec());
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

impl ValueEncoder for u32 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_le_bytes().to_vec());
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

impl ValueEncoder for u64 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_le_bytes().to_vec());
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

impl ValueEncoder for i64 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_le_bytes().to_vec());
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

impl ValueEncoder for [u8; 12] {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_vec());
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

impl ValueEncoder for [u8; 16] {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_vec());
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

impl ValueEncoder for [u8; 32] {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_vec());
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

impl ValueEncoder for [u8; 64] {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_vec());
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

impl ValueEncoder for String {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		let string_length = self.len() as u64;
		vec.append(&mut string_length.to_le_bytes().to_vec());
		vec.append(&mut self.as_bytes().to_vec());
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

impl ValueEncoder for str {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		let string_length = self.len() as u64;
		vec.append(&mut string_length.to_le_bytes().to_vec());
		vec.append(&mut self.as_bytes().to_vec());
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

impl<H> ValueEncoder for Vec<H>
where
	H: HeaderEncoder
{
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut (self.len() as u64).encode_directly());
		for value in self {
			vec.append(&mut value.encode_directly());
		}
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

impl ValueEncoder for Vec<u8> {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut (self.len() as u64).encode_directly());
		for value in self {
			vec.append(&mut value.encode_directly());
		}
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

impl ValueEncoder for Vec<u64> {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut (self.len() as u64).encode_directly());
		for value in self {
			vec.append(&mut value.encode_directly());
		}
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

/// decoder methods for values (and primitive types). This is an extension trait.
pub trait ValueDecoder {
	/// the return value for decode_directly() and decode_for_key();
	type Item;

	/// helper method to check, if the key is on position.
	fn check_key_on_position<K: Into<String>, R: Read>(data: &mut R, key: K) -> bool {
		let key_length = match data.read_u8() {
			Ok(len) => len,
			Err(_) => return false,
		};
		let mut read_key = vec![0u8; key_length as usize];
		match data.read_exact(&mut read_key) {
			Ok(_) => (),
			Err(_) => return false,
		};
		let read_key = match String::from_utf8(read_key) {
			Ok(key) => key,
			Err(_) => return false,
		};
		if read_key == key.into() {
			return true;
		} else {
			return false;
		}
	}

	/// decodes the value directly.
	fn decode_directly<R: Read>(data: &mut R) -> Result<Self::Item>;

	/// decodes the value for the given key.
	fn decode_for_key<K: Into<String>, R: Read>(data: &mut R, key: K) -> Result<Self::Item> {
		if !Self::check_key_on_position(data, key) {
			return Err(ZffError::new(ZffErrorKind::HeaderDecoderKeyNotOnPosition, ERROR_HEADER_DECODER_KEY_POSITION))
		}
		Self::decode_directly(data)
	}
}

impl ValueDecoder for u8 {
	type Item = u8;

	fn decode_directly<R: Read>(data: &mut R) -> Result<u8> {
		Ok(data.read_u8()?)
	}
}

impl ValueDecoder for u16 {
	type Item = u16;

	fn decode_directly<R: Read>(data: &mut R) -> Result<u16> {
		Ok(data.read_u16::<LittleEndian>()?)
	} 
}

impl ValueDecoder for u32 {
	type Item = u32;

	fn decode_directly<R: Read>(data: &mut R) -> Result<u32> {
		Ok(data.read_u32::<LittleEndian>()?)
	}
}

impl ValueDecoder for u64 {
	type Item = u64;

	fn decode_directly<R: Read>(data: &mut R) -> Result<u64> {
		Ok(data.read_u64::<LittleEndian>()?)
	}
}

impl ValueDecoder for i64 {
	type Item = i64;

	fn decode_directly<R: Read>(data: &mut R) -> Result<i64> {
		Ok(data.read_i64::<LittleEndian>()?)
	}
}

impl ValueDecoder for String {
	type Item = String;

	fn decode_directly<R: Read>(data: &mut R) -> Result<String> {
		let length = data.read_u64::<LittleEndian>()?;
		let mut buffer = vec![0u8; length as usize];
		data.read_exact(&mut buffer)?;
		Ok(String::from_utf8(buffer)?)
	}
}

impl ValueDecoder for str {
	type Item = String;

	fn decode_directly<R: Read>(data: &mut R) -> Result<String> {
		let length = u64::decode_directly(data)? as usize;
		let mut buffer = vec![0u8; length as usize];
		data.read_exact(&mut buffer)?;
		Ok(String::from_utf8(buffer)?)
	}
}

impl ValueDecoder for Vec<u8> {
	type Item = Vec<u8>;

	fn decode_directly<R: Read>(data: &mut R) -> Result<Vec<u8>> {
		let length = u64::decode_directly(data)? as usize;
		let mut buffer = vec![0u8; length as usize];
		data.read_exact(&mut buffer)?;
		Ok(buffer)
	}
}

impl ValueDecoder for Vec<u64> {
	type Item = Vec<u64>;

	fn decode_directly<R: Read>(data: &mut R) -> Result<Vec<u64>> {
		let length = u64::decode_directly(data)? as usize;
		let mut vec = Vec::with_capacity(length);
		for _ in 0..length {
			let content = u64::decode_directly(data)?;
			vec.push(content);
		}
		Ok(vec)
	}
}

impl<H> ValueDecoder for Vec<H>
where
	H: HeaderDecoder + HeaderDecoder<Item = H>,
{
	type Item = Vec<H>;

	fn decode_directly<R: Read>(data: &mut R) -> Result<Vec<H>> {
		let length = u64::decode_directly(data)? as usize;
		let mut vec = Vec::with_capacity(length);
		for _ in 0..length {
			let content = H::decode_directly(data)?;
			vec.push(content);
		}
		Ok(vec)
	}
}

/// The ```HeaderDecoder``` trait specifies an interface for the common decoding methods.
pub trait HeaderDecoder: HeaderObject {
	/// the return value for decode_content(), decode_directly(), decode_for_key();
	type Item;

	/// decodes the length of the header.
	fn decode_header_length<R: Read>(data: &mut R) -> Result<u64> {
		match data.read_u64::<LittleEndian>() {
			Ok(value) => Ok(value),
			Err(_) => Err(ZffError::new_header_decode_error(ERROR_HEADER_DECODER_HEADER_LENGTH)),
		}
	}

	/// checks if the read identifier is valid for this header.
	fn check_identifier<R: Read>(data: &mut R) -> bool {
		let identifier = match data.read_u32::<BigEndian>() {
			Ok(val) => val,
			Err(_) => return false,
		};
		if identifier == Self::identifier() { 
			return true;
		} else {
			return false;
		}
	}
	
	/// helper method to check, if the key is on position.
	fn check_key_on_position<K: Into<String>, R: Read>(data: &mut R, key: K) -> bool {
		let key_length = match data.read_u8() {
			Ok(len) => len,
			Err(_) => return false,
		};
		let mut read_key = vec![0u8; key_length as usize];
		match data.read_exact(&mut read_key) {
			Ok(_) => (),
			Err(_) => return false,
		};
		let read_key = match String::from_utf8(read_key) {
			Ok(key) => key,
			Err(_) => return false,
		};
		if read_key == key.into() {
			return true;
		} else {
			return false;
		}
	}

	/// decodes the content of the header.
	fn decode_content(data: Vec<u8>) -> Result<Self::Item>;
	
	/// decodes the header directly.
	fn decode_directly<R: Read>(data: &mut R) -> Result<Self::Item> {
		if !Self::check_identifier(data) {
			return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER));
		}
		let header_length = Self::decode_header_length(data)? as usize;
		let mut header_content = vec![0u8; header_length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
		data.read_exact(&mut header_content)?;
		return Self::decode_content(header_content);
	}

	/// decodes the header for the given key.
	fn decode_for_key<K: Into<String>, R: Read>(data: &mut R, key: K) -> Result<Self::Item> {
		if !Self::check_key_on_position(data, key) {
			return Err(ZffError::new(ZffErrorKind::HeaderDecoderKeyNotOnPosition, ERROR_HEADER_DECODER_KEY_POSITION))
		}
		Self::decode_directly(data)
	}
}