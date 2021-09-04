// - external
use blake2::{Blake2b, Digest};
use sha3::{Sha3_256};
use digest::DynDigest;

#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq,Hash)]
pub enum HashType {
	Blake2b512 = 1,
	SHA3_256 = 2,
}

impl HashType {
	pub fn default_len(&self) -> usize {
		match self {
			HashType::Blake2b512 => 512,
			HashType::SHA3_256 => 256,
		}
	}
}

#[derive(Debug,Clone)]
pub struct Hash;

impl Hash {
	pub fn new_hasher(hash_type: &HashType) -> Box<dyn DynDigest> {
		match hash_type {
			HashType::Blake2b512 => Blake2b::new().box_clone(),
			HashType::SHA3_256 => Sha3_256::new().box_clone(),
		}
	}

	pub fn default_hashtype() -> HashType {
		HashType::Blake2b512
	}
}