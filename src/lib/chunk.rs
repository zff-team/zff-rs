// - internal
use crate::{
	header::ChunkFlags, 
	io::calculate_xxhash, 
	Result,
};

/// This struct represents a full [Chunk] (decrypted and uncompressed) - The raw chunk data, the flags and the size.
pub struct Chunk {
	data: Vec<u8>,
	flags: ChunkFlags,
	size: u64,
}

impl Chunk {
	/// Returns a new [Chunk] with the given values.
	pub fn new(data: Vec<u8>, flags: ChunkFlags, size: u64) -> Chunk {
		Self {
			data,
			flags,
			size
		}
	}

	/// Returns the underlying data.
	pub fn data(&self) -> &Vec<u8> {
		&self.data
	}

	/// Returns the flags.
	pub fn flags(&self) -> &ChunkFlags {
		&self.flags
	}

	/// Returns the size.
	pub fn size(&self) -> u64 {
		self.size
	}

	/// Checks the integrity of the chunk data by calculating the appropriate xxhash hash and comparing it with the given hash.
	///
	/// Returns true if the xxhash hash is equal to the hash in the header, otherwise false. 
	pub fn check_integrity(&self, original_hash: u64) -> Result<bool> {
		let calculated_hash = calculate_xxhash(&self.data);
		Ok(calculated_hash == original_hash)
	}
}

/// This struct represents a prepared [Chunk] (encrypted and compressed).
#[derive(Debug, Clone, Default)]
pub struct PreparedChunk {
	data: Vec<u8>,
	flags: ChunkFlags,
	size: u64,
	xxhash: u64,
	samebytes: Option<u8>,
	duplicated: Option<u64>,
}

impl PreparedChunk {
	/// Returns a new [PreparedChunk] with the given values.
	pub fn new(data: Vec<u8>, flags: ChunkFlags, size: u64, xxhash: u64, samebytes: Option<u8>, duplicated: Option<u64>) -> PreparedChunk {
		Self {
			data,
			flags,
			size,
			xxhash,
			samebytes,
			duplicated
		}
	}

	/// Returns the underlying data.
	pub fn data(&self) -> &Vec<u8> {
		&self.data
	}

	/// Returns the flags.
	pub fn flags(&self) -> &ChunkFlags {
		&self.flags
	}

	/// Returns the size.
	pub fn size(&self) -> u64 {
		self.size
	}

	/// Returns the xxhash value.
	pub fn xxhash(&self) -> u64 {
		self.xxhash
	}

	/// Returns true if the samebytes flag is set, otherwise false.
	pub fn samebytes(&self) -> Option<u8> {
		self.samebytes
	}

	/// Returns the duplicated chunk id, if this chunk is a duplication.
	pub fn duplicated(&self) -> Option<u64> {
		self.duplicated
	}
}

#[derive(Debug, Clone)]
/// The data of the chunk.
pub(crate) enum ChunkContent {
	/// The unencrypted and uncompressed original data of the chunk.
	Raw(Vec<u8>),
	/// The appropriate byte, if the same byte flag is set.
	SameBytes(u8),
	/// The appropriate chunk, if this chunk is a duplication.
	Duplicate(u64),
}
