//! Module for value decoding functionality.
//!
//! This module provides the [`ValueDecoder`] trait which defines an extension trait
//! for decoding primitive values and types from byte streams.

// - STD
use std::io::Read;

// - internal
use crate::prelude::*;

// - external
use byteorder::{ReadBytesExt};

/// decoder methods for values (and primitive types). This is an extension trait.
///
/// # Example
/// ```no_run
/// use zff::ValueDecoder;
/// use std::io::Cursor;
///
/// // Implementing ValueDecoder for a custom type
/// struct MyType(u32);
/// 
/// impl ValueDecoder for MyType {
///     type Item = MyType;
///     fn decode_directly<R: std::io::Read>(data: &mut R) -> zff::Result<MyType> {
///         let bytes = u32::decode_directly(data)?;
///         Ok(MyType(bytes))
///     }
/// }
///
/// let data = vec![42, 0, 0, 0];
/// let mut cursor = Cursor::new(data);
/// let decoded = MyType::decode_directly(&mut cursor).unwrap();
/// assert_eq!(decoded.0, 42);
/// ```
pub trait ValueDecoder {
	/// the return value for decode_directly() and decode_for_key();
	type Item;

	/// helper method to check, if the key is on position.
	///
	/// # Example
	/// ```no_run
	/// use zff::ValueDecoder;
	/// use std::io::Cursor;
	///
	/// let data = vec![5u8, b'h', b'e', b'l', b'l', b'o']; // key length 5, key "hello"
	/// let mut cursor = Cursor::new(data);
	/// let is_on_position = u32::check_key_on_position(&mut cursor, "hello");
	/// assert!(is_on_position);
	/// ```
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
	///
	/// # Example
	/// ```no_run
	/// use zff::ValueDecoder;
	/// use std::io::Cursor;
	///
	/// let data = vec![42, 0, 0, 0];
	/// let mut cursor = Cursor::new(data);
	/// let decoded = u32::decode_directly(&mut cursor).unwrap();
	/// assert_eq!(decoded, 42);
	/// ```
	fn decode_directly<R: Read>(data: &mut R) -> Result<Self::Item>;

	/// decodes the value for the given key.
	///
	/// # Example
	/// ```no_run
	/// use zff::ValueDecoder;
	/// use std::io::Cursor;
	///
	/// // Data with key "value" (length 5) followed by u32 value 42
	/// let data = vec![5, b'v', b'a', b'l', b'u', b'e', 42, 0, 0, 0];
	/// let mut cursor = Cursor::new(data);
	/// let decoded = u32::decode_for_key(&mut cursor, "value").unwrap();
	/// assert_eq!(decoded, 42);
	/// ```
	fn decode_for_key<K: Into<String>, R: Read>(data: &mut R, key: K) -> Result<Self::Item> {
		if !Self::check_key_on_position(data, key) {
			return Err(ZffError::new(ZffErrorKind::KeyNotOnPosition, ERROR_HEADER_DECODER_KEY_POSITION))
		}
		Self::decode_directly(data)
	}


	/// Decodes the value at given offset from ReadAt.
	///
	/// # Example
	/// ```no_run
	/// use zff::{ValueDecoder, ReadAt};
	/// use std::fs::File;
	///
	/// let file = File::open("test.zff").unwrap();
	/// // Decode a u64 value at offset 100
	/// let value = u64::decode_at(&file, 100).unwrap();
	/// ```
	fn decode_at<R: ReadAt + ?Sized>(data: &R, offset: u64) -> Result<Self::Item> {
		let mut cursor = ReadAtCursor::new(data, offset);
		Self::decode_directly(&mut cursor)
	}
}