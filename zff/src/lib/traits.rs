// - internal
use crate::{
	ValueType,
};

pub trait HeaderObject {
	fn identifier() -> u32;
	fn encode_header(&self) -> Vec<u8>;
}

pub trait HeaderEncoder {
	fn encode_key<K: Into<String>>(key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let key = key.into();
		let key_length = key.len() as u8;
		vec.push(key_length);
		vec.append(&mut key.into_bytes());
		vec
	}
	fn encode_directly(&self) -> Vec<u8>;
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = Self::encode_key(key);
		vec.append(&mut encoded_key);
		vec.append(&mut self.encode_directly());
		vec
	}
}

impl HeaderEncoder for u8 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(ValueType::Uint8.as_raw_value());
		vec.push(*self);
		vec
	}
}

impl HeaderEncoder for u32 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(ValueType::Uint32.as_raw_value());
		vec.append(&mut self.to_le_bytes().to_vec());
		vec
	}
}

impl HeaderEncoder for u64 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(ValueType::Uint64.as_raw_value());
		vec.append(&mut self.to_le_bytes().to_vec());
		vec
	}
}

impl HeaderEncoder for String {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		let string_length = self.len() as u32;
		vec.push(ValueType::String.as_raw_value());
		vec.append(&mut string_length.to_le_bytes().to_vec());
		vec.append(&mut self.as_bytes().to_vec());
		vec
	}
}

impl HeaderEncoder for str {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		let string_length = self.len() as u32;
		vec.push(ValueType::String.as_raw_value());
		vec.append(&mut string_length.to_le_bytes().to_vec());
		vec.append(&mut self.as_bytes().to_vec());
		vec
	}
}