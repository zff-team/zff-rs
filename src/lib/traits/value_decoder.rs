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