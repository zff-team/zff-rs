// - STD
use std::io::Read;
use std::collections::{HashMap, BTreeMap, BTreeSet};

// - internal
use crate::{
	Result, ZffError, ZffErrorKind,
};

// - external
use itertools::Itertools;
#[cfg(feature = "log")]
use log::trace;

use crate::constants::*;

// - external
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};

/// The ```HeaderCoding``` trait specifies an interface for the common header methods and the encoding and decoding methods.
pub trait HeaderCoding {
	/// the return value for decode_content(), decode_directly(), decode_for_key();
	type Item;

	/// returns the identifier (=Magic bytes) of the header.
	fn identifier() -> u32;
	/// encodes the header.
	fn encode_header(&self) -> Vec<u8>;

	/// returns the size of the encoded header (in bytes)
	fn header_size(&self) -> usize {
		self.encode_directly().len()
	}

	/// returns the version of the header.
	/// This reflects the default version of the appropiate header used in zff v3.
	fn version() -> u8;

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

	/// decodes the length of the header.
	fn decode_header_length<R: Read>(data: &mut R) -> Result<u64> {
		match data.read_u64::<LittleEndian>() {
			Ok(value) => Ok(value),
			Err(_) => Err(ZffError::new(ZffErrorKind::EncodingError, ERROR_HEADER_DECODER_HEADER_LENGTH)),
		}
	}

	/// checks if the read identifier is valid for this header.
	fn check_identifier<R: Read>(data: &mut R) -> bool {
		let identifier = match data.read_u32::<BigEndian>() {
			Ok(val) => val,
			Err(_) => return false,
		};
		#[cfg(feature = "log")]
		log::trace!("Read identifier: {:x}", identifier);
		identifier == Self::identifier()
	}

	/// checks if the read header / footer version is supported by this crate (only zff v3 headers / footers are supported).
	fn check_version<R: Read>(data: &mut R) -> Result<()> {
		let version = match data.read_u8() {
			Ok(val) => val,
			Err(_) => return Err(ZffError::new(ZffErrorKind::EncodingError, ERROR_HEADER_DECODER_HEADER_LENGTH)),
		};
		if version != Self::version() {
			return Err(ZffError::new(ZffErrorKind::Unsupported, format!("{ERROR_UNSUPPORTED_VERSION}{version}")));
		}
		Ok(())
	}

	/// decodes the content of the header.
	fn decode_content(data: Vec<u8>) -> Result<Self::Item>;
	
	/// decodes the header directly.
	fn decode_directly<R: Read>(data: &mut R) -> Result<Self::Item> {
		#[cfg(feature = "log")]
    	trace!("Trying to decode a {}", Self::struct_name());

		if !Self::check_identifier(data) {
			return Err(ZffError::new(ZffErrorKind::Invalid, ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER));
		}
		let header_length = Self::decode_header_length(data)? as usize;
		let mut header_content = vec![0u8; header_length-DEFAULT_LENGTH_HEADER_IDENTIFIER-DEFAULT_LENGTH_VALUE_HEADER_LENGTH];
		data.read_exact(&mut header_content)?;
		Self::decode_content(header_content)
	}

	/// Method to show the "name" of the appropriate struct (e.g. to use this with fmt::Display).
	/// This method is a necassary helper method for fmt::Display and serde::ser::SerializeStruct (and for some debugging purposes).
	fn struct_name() -> &'static str;
}

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
		read_key == key.into()
	}

	/// decodes the value directly.
	fn decode_directly<R: Read>(data: &mut R) -> Result<Self::Item>;

	/// decodes the value for the given key.
	fn decode_for_key<K: Into<String>, R: Read>(data: &mut R, key: K) -> Result<Self::Item> {
		if !Self::check_key_on_position(data, key) {
			return Err(ZffError::new(ZffErrorKind::KeyNotOnPosition, ERROR_HEADER_DECODER_KEY_POSITION))
		}
		Self::decode_directly(data)
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
}

/// encodes a given key.
fn encode_key(key: &str) -> Vec<u8> {
	let mut vec = Vec::new();
	let key_length = key.len() as u8;
	vec.push(key_length);
	vec.append(&mut key.as_bytes().to_vec());
	vec
}