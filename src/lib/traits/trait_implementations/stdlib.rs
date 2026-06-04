// ! Contains all implementations of zff defined traits for types of stdlib (e.g. primitives, Vec, HashMap, etc.).

// - STD
use std::collections::{BTreeMap, HashMap};
use std::io::{Read};

// - internal
use crate::prelude::*;

// - external
use byteorder::{LittleEndian, ReadBytesExt};
use itertools::Itertools;

impl ValueEncoder for bool {
	fn encode_directly(&self) -> Vec<u8> {
		vec![u8::from(*self)]
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_BOOL
	}

	fn encoded_size(&self) -> usize {
		1
	}
}

impl ValueEncoder for u8 {
	fn encode_directly(&self) -> Vec<u8> {
		vec![*self]
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_U8
	}

	fn encoded_size(&self) -> usize {
		1
	}
}

impl ValueEncoder for u16 {
	fn encode_directly(&self) -> Vec<u8> {
		self.to_le_bytes().to_vec()
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_U16
	}

	fn encoded_size(&self) -> usize {
		2
	}
}

impl ValueEncoder for u32 {
	fn encode_directly(&self) -> Vec<u8> {
		self.to_le_bytes().to_vec()
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_U32
	}

	fn encoded_size(&self) -> usize {
		4
	}
}

impl ValueEncoder for u64 {
	fn encode_directly(&self) -> Vec<u8> {
		self.to_le_bytes().to_vec()
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_U64
	}

	fn encoded_size(&self) -> usize {
		8
	}
}

impl ValueEncoder for i8 {
	fn encode_directly(&self) -> Vec<u8> {
		vec![*self as u8]
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_I8
	}

	fn encoded_size(&self) -> usize {
		1
	}
}

impl ValueEncoder for i16 {
	fn encode_directly(&self) -> Vec<u8> {
		self.to_le_bytes().to_vec()
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_I16
	}

	fn encoded_size(&self) -> usize {
		2
	}
}

impl ValueEncoder for i32 {
	fn encode_directly(&self) -> Vec<u8> {
		self.to_le_bytes().to_vec()
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_I32
	}

	fn encoded_size(&self) -> usize {
		4
	}
}

impl ValueEncoder for i64 {
	fn encode_directly(&self) -> Vec<u8> {
		self.to_le_bytes().to_vec()
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_I64
	}

	fn encoded_size(&self) -> usize {
		8
	}
}

impl ValueEncoder for f32 {
	fn encode_directly(&self) -> Vec<u8> {
		self.to_le_bytes().to_vec()
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_F32
	}

	fn encoded_size(&self) -> usize {
		4
	}
}

impl ValueEncoder for f64 {
	fn encode_directly(&self) -> Vec<u8> {
		self.to_le_bytes().to_vec()
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_F64
	}

	fn encoded_size(&self) -> usize {
		8
	}
}

impl ValueEncoder for [u8; 12] {
	fn encode_directly(&self) -> Vec<u8> {
		self.to_vec()
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_BYTEARRAY
	}

	fn encoded_size(&self) -> usize {
		12
	}
}

impl ValueEncoder for [u8; 16] {
	fn encode_directly(&self) -> Vec<u8> {
		self.to_vec()
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_BYTEARRAY
	}

	fn encoded_size(&self) -> usize {
		16
	}
}

impl ValueEncoder for [u8; 32] {
	fn encode_directly(&self) -> Vec<u8> {
		self.to_vec()
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_BYTEARRAY
	}

	fn encoded_size(&self) -> usize {
		32
	}
}

impl ValueEncoder for [u8; 64] {
	fn encode_directly(&self) -> Vec<u8> {
		self.to_vec()
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_BYTEARRAY
	}

	fn encoded_size(&self) -> usize {
		64
	}
}

impl ValueEncoder for String {
	fn encode_directly(&self) -> Vec<u8> {
		let string_length = self.len();
		let mut vec = Vec::with_capacity(string_length + 8);
		vec.extend_from_slice(&string_length.to_le_bytes());
		vec.extend_from_slice(self.as_bytes());
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_STRING
	}

	fn encoded_size(&self) -> usize {
		8 + self.len()
	}
}

impl ValueEncoder for str {
	fn encode_directly(&self) -> Vec<u8> {
		let string_length = self.len();
		let mut vec = Vec::with_capacity(string_length + 8);
		vec.extend_from_slice(&string_length.to_le_bytes());
		vec.extend_from_slice(self.as_bytes());
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_STRING
	}

	fn encoded_size(&self) -> usize {
		8 + self.len()
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

	fn encoded_size(&self) -> usize {
		8 + self.len()
	}
}

impl ValueEncoder for Vec<u64> {
	fn encode_directly(&self) -> Vec<u8> {
		let mut vec = Vec::with_capacity(8 + self.len() * 8);
		vec.extend_from_slice(&(self.len() as u64).to_le_bytes());

		for value in self {
			vec.extend_from_slice(&value.to_le_bytes());
		}
		vec
	}

	fn identifier(&self) -> u8 {
		METADATA_EXT_TYPE_IDENTIFIER_VEC
	}

	fn encode_with_identifier(&self) -> Vec<u8> {
		let mut vec = Vec::with_capacity(1 + 8 + self.len() * 9);
		vec.push(self.identifier());
		vec.extend_from_slice(&(self.len() as u64).to_le_bytes());

		for value in self {
			vec.push(value.identifier());
			vec.extend_from_slice(&value.to_le_bytes());
		}
		vec
	}

	fn encoded_size(&self) -> usize {
		8 + self.len() * 8
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

	fn encoded_size(&self) -> usize {
		8 + self
			.iter()
			.map(|(key, value)| key.encoded_size() + value.encoded_size())
			.sum::<usize>()
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

	fn encoded_size(&self) -> usize {
		8 + self
			.iter()
			.map(|(key, value)| key.encoded_size() + value.encoded_size())
			.sum::<usize>()
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

	fn encoded_size(&self) -> usize {
		8 + self
			.iter()
			.map(|(key, (value_a, value_b))| {
				key.encoded_size() + value_a.encoded_size() + value_b.encoded_size()
			})
			.sum::<usize>()
	}
}

// TOOD: Check if this can be removed:
/*
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

	fn encoded_size(&self) -> usize {
		8 + self.iter().map(ValueEncoder::encoded_size).sum::<usize>()
	}
}*/

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

	fn encoded_size(&self) -> usize {
		8 + self.iter().map(HeaderCoding::header_size).sum::<usize>()
	}
}

impl ValueDecoder for bool {
	type Item = bool;

	fn decode_directly<R: Read>(data: &mut R) -> Result<bool> {
		let data = data.read_u8()?;
		Ok(data != 0)
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

impl ValueDecoder for i8 {
	type Item = i8;

	fn decode_directly<R: Read>(data: &mut R) -> Result<Self::Item> {
		Ok(data.read_i8()?)
	}
}

impl ValueDecoder for i16 {
	type Item = i16;

	fn decode_directly<R: Read>(data: &mut R) -> Result<i16> {
		Ok(data.read_i16::<LittleEndian>()?)
	}
}

impl ValueDecoder for i32 {
	type Item = i32;

	fn decode_directly<R: Read>(data: &mut R) -> Result<i32> {
		Ok(data.read_i32::<LittleEndian>()?)
	}
}

impl ValueDecoder for i64 {
	type Item = i64;

	fn decode_directly<R: Read>(data: &mut R) -> Result<i64> {
		Ok(data.read_i64::<LittleEndian>()?)
	}
}

impl ValueDecoder for f32 {
	type Item = f32;

	fn decode_directly<R: Read>(data: &mut R) -> Result<f32> {
		Ok(data.read_f32::<LittleEndian>()?)
	}
}

impl ValueDecoder for f64 {
	type Item = f64;

	fn decode_directly<R: Read>(data: &mut R) -> Result<Self::Item> {
		Ok(data.read_f64::<LittleEndian>()?)
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
		let mut buffer = vec![0u8; length];
		data.read_exact(&mut buffer)?;
		Ok(String::from_utf8(buffer)?)
	}
}

impl ValueDecoder for Vec<u8> {
	type Item = Vec<u8>;

	fn decode_directly<R: Read>(data: &mut R) -> Result<Vec<u8>> {
		let length = u64::decode_directly(data)? as usize;
		let mut buffer = vec![0u8; length];
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

impl<K, V> ValueDecoder for HashMap<K, V>
where
	K: ValueDecoder<Item = K> + std::cmp::Eq + std::hash::Hash,
	V: ValueDecoder<Item = V>,
{

	type Item = HashMap<K, V>;

	fn decode_directly<R: Read>(data: &mut R) -> Result<HashMap<K, V>> {
		let length = u64::decode_directly(data)? as usize;
		let mut hash_map = HashMap::new();
		hash_map.try_reserve(length)?;
		for _ in 0..length {
			let key = K::decode_directly(data)?;
			let value = V::decode_directly(data)?;
			hash_map.insert(key, value);
		}
		hash_map.shrink_to_fit();
		Ok(hash_map)
	}
}

impl<K, V> ValueDecoder for BTreeMap<K, V>
where
	K: ValueDecoder<Item = K> + std::cmp::Ord,
	V: ValueDecoder<Item = V>
{

	type Item = BTreeMap<K, V>;

	fn decode_directly<R: Read>(data: &mut R) -> Result<BTreeMap<K, V>> {
		let length = u64::decode_directly(data)? as usize;
		let mut btreemap = BTreeMap::new();
		for _ in 0..length {
			let key = K::decode_directly(data)?;
			let value = V::decode_directly(data)?;
			btreemap.insert(key, value);
		}
		Ok(btreemap)
	}
}

impl<A, B> ValueDecoder for (A, B) 
where
	A: ValueDecoder<Item = A>,
	B: ValueDecoder<Item = B>,
{
	type Item = (A, B);

	fn decode_directly<R: Read>(data: &mut R) -> Result<(A, B)> {
		let a = A::decode_directly(data)?;
		let b = B::decode_directly(data)?;
		Ok((a, b))
	}
}

//TODO: check if this can be removed.
/*
impl<K, A, B> ValueDecoder for BTreeSet<BTreeMap<K, (A, B)>>
where
	K: ValueDecoder<Item = K> + std::cmp::Ord,
	A: ValueDecoder<Item = A> + std::cmp::Ord,
	B: ValueDecoder<Item = B> + std::cmp::Ord,
{
	type Item = BTreeSet<BTreeMap<K, (A, B)>>;

	fn decode_directly<R: Read>(data: &mut R) -> Result<BTreeSet<BTreeMap<K, (A, B)>>>
	{
		let length = u64::decode_directly(data)? as usize;
		let mut btree_set = BTreeSet::new();
		for _ in 0..length {
			let map = BTreeMap::decode_directly(data)?;
			btree_set.insert(map);
		}
		Ok(btree_set)
	}
}*/

impl<H> ValueDecoder for Vec<H>
where
	H: HeaderCoding<Item = H>,
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

/// implements Encryption for `Vec<u8>` to use this for chunk content data
impl Encryption for Vec<u8> {
	fn crypto_nonce_padding() -> u8 {
		0b00000000
	}
}