pub enum ValueType {
	Uint8,
}

impl ValueType {
	fn as_raw_value(&self) -> u8 {
		match self {
			ValueType::Uint8 => 0,
		}
	}
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
		vec.push(ValueType::Uint8.as_raw_value());
		vec.push(*self);
		vec
	}

	fn encode_for_key<K: Into<String>>(&self, key: K) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = Self::encode_key(key);
		vec.append(&mut encoded_key);
		vec.push(ValueType::Uint8.as_raw_value());
		vec.push(*self);
		vec
	}
}