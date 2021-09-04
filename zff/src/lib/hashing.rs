// - external
use blake2::{Blake2b, Digest};
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256};
use digest::DynDigest;

#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq,Hash)]
pub enum HashType {
	Blake2b512 = 1,
	SHA256 = 2,
	SHA512 = 3,
	SHA3_256 = 4,
}

impl HashType {
	pub fn default_len(&self) -> usize {
		match self {
			HashType::Blake2b512 => 512,
			HashType::SHA256 => 256,
			HashType::SHA512 => 512,
			HashType::SHA3_256 => 256,
		}
	}
}

#[derive(Debug,Clone)]
pub struct Hash;

impl Hash {
	pub fn new_hasher(hash_type: &HashType) -> Box<dyn DynDigest> {
		match hash_type {
			HashType::Blake2b512 => Box::new(Blake2b::new()),
			HashType::SHA256 => Box::new(Sha256::new()),
			HashType::SHA512 => Box::new(Sha512::new()),
			HashType::SHA3_256 => Box::new(Sha3_256::new()),
		}
	}

	pub fn default_hashtype() -> HashType {
		HashType::Blake2b512
	}
}