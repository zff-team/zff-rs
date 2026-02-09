// - Parent
use super::*;

/// encoder methods for values (and primitive types). This is an extension trait.
pub trait ValueEncoder {
	/// encodes the value directly (= without key).
	fn encode_directly(&self) -> Vec<u8>;
	/// encodes a key to the value.
	fn encode_for_key(&self, key: &str) -> Vec<u8> {
		let mut vec = Vec::new();
		let mut encoded_key = encode_key(key);
		vec.append(&mut encoded_key);
		vec.append(&mut self.encode_directly());
		vec
	}

	/// encodes with the appropriate type identifier.
	fn encode_with_identifier(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(self.identifier());
		vec.append(&mut self.encode_directly());
		vec
	}

	/// returns the identifier of the appropiate type.
	fn identifier(&self) -> u8;
}

impl ValueEncoder for bool {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		if *self {
			vec.push(1_u8);
		} else {
			vec.push(0_u8);
		};
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_BOOL
	}
}

impl ValueEncoder for u8 {
	fn encode_directly(&self) -> Vec<u8> {
		vec![*self]
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_U8
	}
}

impl ValueEncoder for u16 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_le_bytes().to_vec());
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_U16
	}
}

impl ValueEncoder for u32 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_le_bytes().to_vec());
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_U32
	}
}

impl ValueEncoder for u64 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_le_bytes().to_vec());
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_U64
	}
}

impl ValueEncoder for i8 {
	fn encode_directly(&self) -> Vec<u8> {
		vec![*self as u8]
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_I8
	}
}

impl ValueEncoder for i16 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_le_bytes().to_vec());
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_I16
	}
}

impl ValueEncoder for i32 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_le_bytes().to_vec());
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_I32
	}
}

impl ValueEncoder for i64 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_le_bytes().to_vec());
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_I64
	}
}

impl ValueEncoder for f32 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_le_bytes().to_vec());
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_F32
	}
}

impl ValueEncoder for f64 {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_le_bytes().to_vec());
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_F64
	}
}

impl ValueEncoder for [u8; 12] {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_vec());
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_BYTEARRAY
	}
}

impl ValueEncoder for [u8; 16] {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_vec());
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_BYTEARRAY
	}
}

impl ValueEncoder for [u8; 32] {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_vec());
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_BYTEARRAY
	}
}

impl ValueEncoder for [u8; 64] {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut self.to_vec());
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_BYTEARRAY
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

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_STRING
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

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_STRING
	}
}

impl<H> ValueEncoder for Vec<H>
where
	H: HeaderCoding
{
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut (self.len() as u64).encode_directly());
		for value in self {
			vec.append(&mut value.encode_directly());
		}
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_VEC
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

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_BYTEARRAY
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

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_VEC
	}

	fn encode_with_identifier(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(self.identifier());
		vec.append(&mut (self.len() as u64).encode_directly());
		for value in self {
			vec.append(&mut value.encode_with_identifier());
		}
		vec
	}
}

impl<K, V> ValueEncoder for HashMap<K, V>
where
	K: ValueEncoder + std::cmp::Ord,
	V: ValueEncoder + std::cmp::Ord
{
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut (self.len() as u64).encode_directly());
		for (key, value) in self.iter().sorted() {
			vec.append(&mut key.encode_directly());
			vec.append(&mut value.encode_directly());
		}
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_HASHMAP
	}

	fn encode_with_identifier(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(self.identifier());
		vec.append(&mut (self.len() as u64).encode_directly());
		for (key, value) in self.iter() {
			vec.append(&mut key.encode_with_identifier());
			vec.append(&mut value.encode_with_identifier());
		}
		vec
	}
}

impl<K, V> ValueEncoder for BTreeMap<K, V>
where
	K: ValueEncoder,
	V: ValueEncoder
{
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut (self.len() as u64).encode_directly());
		for (key, value) in self.iter() {
			vec.append(&mut key.encode_directly());
			vec.append(&mut value.encode_directly());
		}
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_BTREEMAP
	}

	fn encode_with_identifier(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.push(self.identifier());
		vec.append(&mut (self.len() as u64).encode_directly());
		for (key, value) in self.iter() {
			vec.append(&mut key.encode_with_identifier());
			vec.append(&mut value.encode_with_identifier());
		}
		vec
	}
}

impl<K, A, B> ValueEncoder for BTreeMap<K, (A, B)> 
where
	K: ValueEncoder,
	A: ValueEncoder,
	B: ValueEncoder
{
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut (self.len() as u64).encode_directly());
		for (key, (value_a, value_b)) in self.iter() {
			vec.append(&mut key.encode_directly());
			vec.append(&mut value_a.encode_directly());
			vec.append(&mut value_b.encode_directly());
		}
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_BTREEMAP
	}

}

impl <K, A, B> ValueEncoder for BTreeSet<BTreeMap<K, (A, B)>> 
where
	K: ValueEncoder,
	A: ValueEncoder,
	B: ValueEncoder
{
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::new();
		vec.append(&mut (self.len() as u64).encode_directly());
		for map in self.iter() {
			vec.append(&mut map.encode_directly());
		}
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_VEC
	}
}