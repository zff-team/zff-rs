//! Module for cryptographic hashing operations in zff.
//!
//! This module provides hashing functionality using various cryptographic algorithms
//! for data integrity verification in zff containers.
//!
//! # Types
//!
//! - [`HashType`]: Enum defining all supported hashing algorithms (Blake2b512, SHA256, SHA512, SHA3_256, Blake3)
//! - [`Hash`]: Structure containing methods to create hashers for different algorithms
//!
//! # Features
//!
//! - Support for multiple hash algorithms with configurable default
//! - Integration with the `digest` trait for consistent hashing operations
//! - Optional serialization support with the `serde` feature

// - STD
use std::fmt;

// - external
use blake2::Blake2b512;
use blake3::{Hasher as Blake3};
use digest::{DynDigest, Digest};
#[cfg(feature = "log")]
use log::{debug};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256};

/// Defines all hashing algorithms, which are implemented in zff.
///
/// # Example
/// ```
/// use zff::HashType;
///
/// // All available hash types
/// let blake2b512 = HashType::Blake2b512;
/// let sha256 = HashType::SHA256;
/// let sha512 = HashType::SHA512;
/// let sha3_256 = HashType::SHA3_256;
/// let blake3 = HashType::Blake3;
///
/// // Get the default length for each algorithm
/// assert_eq!(HashType::SHA256.default_len(), 256);
/// assert_eq!(HashType::SHA512.default_len(), 512);
/// assert_eq!(HashType::Blake3.default_len(), 256);
///
/// // Display formatting
/// assert_eq!(format!("{}", HashType::Blake3), "Blake3");
/// ```
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq,Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum HashType {
	/// The Blake2b-512 algorithm with the encoding value 0.
	Blake2b512 = 0,
	/// The SHA256 algorithm with the encoding value 1.
	SHA256 = 1,
	/// The SHA512 algorithm with the encoding value 2.
	SHA512 = 2,
	/// The SHA3-256 (keccak) algorithm with the encoding value 3.
	SHA3_256 = 3,
	/// The blake3 algorithm with the encoding value 4.
	Blake3 = 4,
}

impl HashType {
	/// returns the default length of the appropriate hash (as bits).
	pub fn default_len(&self) -> usize {
		match self {
			HashType::Blake2b512 => 512,
			HashType::SHA256 => 256,
			HashType::SHA512 => 512,
			HashType::SHA3_256 => 256,
			HashType::Blake3 => 256,
		}
	}
}

impl fmt::Display for HashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let msg = match self {
			HashType::Blake2b512 => "Blake2b512",
			HashType::SHA256 => "SHA256",
			HashType::SHA512 => "SHA512",
			HashType::SHA3_256 => "Sha3_256",
			HashType::Blake3 => "Blake3"
		};
		write!(f, "{}", msg)
	}
}

/// structure contains serveral methods to handle hashing
#[derive(Debug,Clone)]
pub struct Hash;

impl Hash {
	/// returns a new Hasher which implements [DynDigest](https://docs.rs/digest/0.9.0/digest/trait.DynDigest.html).
	///
	/// # Example
	/// ```
	/// use zff::{Hash, HashType};
	/// use digest::DynDigest;
	///
	/// // Create a new SHA256 hasher
	/// let mut hasher = Hash::new_hasher(&HashType::SHA256);
	/// hasher.update(b"Hello, World!");
	/// let hash_result = hasher.finalize();
	/// // The hash is now a byte vector containing the SHA256 hash
	/// ```
	pub fn new_hasher(hash_type: &HashType) -> Box<dyn DynDigest> {
		match hash_type {
			HashType::Blake2b512 => Box::new(Blake2b512::new()),
			HashType::SHA256 => Box::new(Sha256::new()),
			HashType::SHA512 => Box::new(Sha512::new()),
			HashType::SHA3_256 => Box::new(Sha3_256::new()),
			HashType::Blake3 => Box::new(Blake3::new()),
		}
	}

	/// returns the default hashtype of zff.
	///
	/// # Example
	/// ```
	/// use zff::{Hash, HashType};
	///
	/// // Get the default hash type
	/// let default_hash = Hash::default_hashtype();
	/// assert!(matches!(default_hash, HashType::Blake3));
	/// ```
	pub fn default_hashtype() -> HashType {
		HashType::Blake3
	}
}

#[cfg(feature = "log")]
pub(crate) fn hashes_to_log(object_no: u64, file_no: Option<u64>, values: &Vec<crate::header::HashValue>) {
	for value in values {
		if let Some(file_no) = file_no {
			debug!("{} hash for object {object_no} / file {file_no} finalized: {}", value.hash_type(), hex::encode(value.hash()));
		} else {
			debug!("{} hash for object {object_no} finalized: {}", value.hash_type(), hex::encode(value.hash()));
		}
	}
}