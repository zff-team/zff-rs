//! Module containing traits used throughout the zff crate.
//!
//! This module defines the core traits that enable the extensible and flexible
//! architecture of zff. Traits are used for encoding/decoding, encryption, reading,
//! and handling various types of objects.
//!
//! This module contains submodules: header_coding, logical_object_source, encryption,
//! read_at, trait_implementations, value_decoder, value_encoder, virtual_object_source.
//!
//! All traits from the submodules are re-exported here for convenient access.

// - modules
mod encryption;
mod header_coding;
mod logical_object_source;
mod trait_implementations;
mod value_decoder;
mod value_encoder;
mod virtual_object_source;

// - re-exports
pub use encryption::*;
pub use header_coding::*;
pub use logical_object_source::*;
pub use value_decoder::*;
pub use value_encoder::*;
pub use virtual_object_source::*;

/// encodes a given key.
fn encode_key(key: &str) -> Vec<u8> {
    let mut vec = Vec::new();
    let key_length = key.len() as u8;
    vec.push(key_length);
    vec.append(&mut key.as_bytes().to_vec());
    vec
}
