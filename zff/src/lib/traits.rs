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
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8>;

}

impl HeaderEncoder for u8 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(*self);
		vec
	}
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = Self::encode_key(key);
		vec.append(&mut encoded_key);
		vec.push(ValueType::Uint8.clone() as u8);
		vec.append(&mut self.encode_directly());
		vec
	}
}

impl HeaderEncoder for u16 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_le_bytes().to_vec());
		vec
	}
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = Self::encode_key(key);
		vec.append(&mut encoded_key);
		vec.push(ValueType::Uint16.clone() as u8);
		vec.append(&mut self.encode_directly());
		vec
	}
}

impl HeaderEncoder for u32 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_le_bytes().to_vec());
		vec
	}
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = Self::encode_key(key);
		vec.append(&mut encoded_key);
		vec.push(ValueType::Uint32.clone() as u8);
		vec.append(&mut self.encode_directly());
		vec
	}
}

impl HeaderEncoder for u64 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_le_bytes().to_vec());
		vec
	}
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = Self::encode_key(key);
		vec.append(&mut encoded_key);
		vec.push(ValueType::Uint64.clone() as u8);
		vec.append(&mut self.encode_directly());
		vec
	}
}

impl HeaderEncoder for [u8; 12] {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_vec());
		vec
	}
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = Self::encode_key(key);
		vec.append(&mut encoded_key);
		vec.push(ValueType::Bytes.clone() as u8);
		vec.append(&mut self.encode_directly());
		vec
	}
}

impl HeaderEncoder for [u8; 16] {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_vec());
		vec
	}
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = Self::encode_key(key);
		vec.append(&mut encoded_key);
		vec.push(ValueType::Bytes.clone() as u8);
		vec.append(&mut self.encode_directly());
		vec
	}
}

impl HeaderEncoder for [u8; 32] {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_vec());
		vec
	}
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = Self::encode_key(key);
		vec.append(&mut encoded_key);
		vec.push(ValueType::Bytes.clone() as u8);
		vec.append(&mut self.encode_directly());
		vec
	}
}

impl HeaderEncoder for Vec<u8> {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut (self.len() as u32).encode_directly());
		vec.append(&mut self.to_vec());
		vec
	}
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = Self::encode_key(key);
		vec.append(&mut encoded_key);
		vec.push(ValueType::Bytes.clone() as u8);
		vec.append(&mut self.encode_directly());
		vec
	}
}

impl HeaderEncoder for String {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		let string_length = self.len() as u32;
		vec.append(&mut string_length.to_le_bytes().to_vec());
		vec.append(&mut self.as_bytes().to_vec());
		vec
	}
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = Self::encode_key(key);
		vec.append(&mut encoded_key);
		vec.push(ValueType::String.clone() as u8);
		vec.append(&mut self.encode_directly());
		vec
	}
}

impl HeaderEncoder for str {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		let string_length = self.len() as u32;
		vec.append(&mut string_length.to_le_bytes().to_vec());
		vec.append(&mut self.as_bytes().to_vec());
		vec
	}
	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = Self::encode_key(key);
		vec.append(&mut encoded_key);
		vec.push(ValueType::String.clone() as u8);
		vec.append(&mut self.encode_directly());
		vec
	}
}

pub trait Unbox<T> {
	fn unbox(self) -> T;
}

impl<T> Unbox<T> for Box<T> {
	fn unbox(self) -> T {
		*self
	}
}