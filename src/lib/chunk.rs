// - STD
use std::borrow::Borrow;

// - internal
use crate::{
	header::{CRC32Value, ChunkFlags}, 
	CompressionAlgorithm, 
	Result,
};

/// This struct represents a full [Chunk] (decrypted and uncompressed).
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

	/// Checks the integrity of the chunk data by calculating the appropriate crc32 hash.
	///
	/// Returns true if the crc32 hash is equal to the hash in the header, otherwise false. 
	pub fn check_integrity<C>(&self) -> Result<bool> 
	where
		C: Borrow<CompressionAlgorithm>,
	{
		todo!()
	}
}

/// This struct represents a prepared [Chunk] (encrypted and compressed).
#[derive(Debug, Clone)]
pub struct PreparedChunk {
	data: Vec<u8>,
	flags: ChunkFlags,
	size: u64,
	crc: CRC32Value,
}

impl PreparedChunk {
	/// Returns a new [PreparedChunk] with the given values.
	pub fn new(data: Vec<u8>, flags: ChunkFlags, size: u64, crc: CRC32Value) -> PreparedChunk {
		Self {
			data,
			flags,
			size,
			crc
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

	/// Returns the crc32 value.
	pub fn crc(&self) -> &CRC32Value {
		&self.crc
	}
}