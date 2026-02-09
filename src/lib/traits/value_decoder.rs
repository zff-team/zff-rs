// - Parent
use super::*;

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