// - external
use blake2::{Blake2b, Digest};
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256};
use digest::DynDigest;

/// Defines all hashing algorithms, which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq,Hash)]
pub enum HashType {
	/// The Blake2b-512 algorithm with the encoding value 1.
	Blake2b512 = 1,
	/// The SHA256 algorithm with the encoding value 2.
	SHA256 = 2,
	/// The SHA512 algorithm with the encoding value 3.
	SHA512 = 3,
	/// The SHA3-256 (keccak) algorithm with the encoding value 4.
	SHA3_256 = 4,
}

impl HashType {
	/// returns the default length of the appropriate hash (as bits).
	pub fn default_len(&self) -> usize {
		match self {
			HashType::Blake2b512 => 512,
			HashType::SHA256 => 256,
			HashType::SHA512 => 512,
			HashType::SHA3_256 => 256,
		}
	}
}

/// structure contains serveral methods to handle hashing
#[derive(Debug,Clone)]
pub struct Hash;

impl Hash {
	/// returns a new Hasher which implements [DynDigest](https://docs.rs/digest/0.9.0/digest/trait.DynDigest.html).
	pub fn new_hasher(hash_type: &HashType) -> Box<dyn DynDigest> {
		match hash_type {
			HashType::Blake2b512 => Box::new(Blake2b::new()),
			HashType::SHA256 => Box::new(Sha256::new()),
			HashType::SHA512 => Box::new(Sha512::new()),
			HashType::SHA3_256 => Box::new(Sha3_256::new()),
		}
	}

	/// returns the default hashtype of zff.
	pub fn default_hashtype() -> HashType {
		HashType::Blake2b512
	}
}