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