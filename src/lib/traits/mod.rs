// - Parent
use super::*;

// - modules
mod header_coding;
mod logical_object_source;
mod value_decoder;
mod value_encoder;

// - re-exports
pub use header_coding::*;
pub use logical_object_source::*;
pub use value_decoder::*;
pub use value_encoder::*;

/// encodes a given key.
fn encode_key(key: &str) -> Vec<u8> {
	let mut vec = Vec::new();
	let key_length = key.len() as u8;
	vec.push(key_length);
	vec.append(&mut key.as_bytes().to_vec());
	vec
}