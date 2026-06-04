//! Module for handling chunk data in zff containers.
//!
//! Chunks are the fundamental data units in zff containers. This module provides
//! structures and functionality for working with both raw and prepared chunks.
//!
//! # Types
//!
//! - [`Chunk`]: A full chunk with raw data, flags, and size (decrypted and uncompressed)
//! - [`PreparedChunk`]: A chunk that has been encrypted and compressed, ready for storage
//! - [`ChunkContent`]: Enum representing different types of chunk content

// - Parent
use super::{*, header::*, io::*};

/// This struct represents a full [Chunk] (decrypted and uncompressed) - The raw chunk data, the flags and the size.
///
/// # Example
/// ```no_run
/// use zff::{Chunk, header::ChunkFlags};
///
/// // Create a new chunk with data
/// let data = vec![1, 2, 3, 4, 5];
/// let flags = ChunkFlags::new();
/// let chunk = Chunk::new(data, flags, 1024);
///
/// // Access chunk properties
/// assert_eq!(chunk.size(), 1024);
/// assert_eq!(chunk.data().len(), 5);
/// ```
pub struct Chunk {
	data: Vec<u8>,
	flags: ChunkFlags,
	size: u64,
}

impl Chunk {
	/// Returns a new [Chunk] with the given values.
	///
	/// # Example
	/// ```no_run
	/// use zff::{Chunk, header::ChunkFlags};
	///
	/// let data = vec![1u8; 4096]; // 4KB of data
	/// let flags = ChunkFlags::new();
	/// let chunk = Chunk::new(data, flags, 4096);
	/// ```
	pub fn new(data: Vec<u8>, flags: ChunkFlags, size: u64) -> Chunk {
		Self {
			data,
			flags,
			size
		}
	}

	/// Returns the underlying data.
	///
	/// # Example
	/// ```no_run
	/// use zff::{Chunk, header::ChunkFlags};
	///
	/// let chunk = Chunk::new(vec![1, 2, 3], ChunkFlags::new(), 1024);
	/// let data = chunk.data();
	/// assert_eq!(data.len(), 3);
	/// ```
	pub fn data(&self) -> &Vec<u8> {
		&self.data
	}

	/// Returns the flags.
	///
	/// # Example
	/// ```no_run
	/// use zff::{Chunk, header::ChunkFlags};
	///
	/// let chunk = Chunk::new(vec![], ChunkFlags::new(), 1024);
	/// let flags = chunk.flags();
	/// // flags contains the chunk flags
	/// ```
	pub fn flags(&self) -> &ChunkFlags {
		&self.flags
	}

	/// Returns the size.
	///
	/// # Example
	/// ```no_run
	/// use zff::{Chunk, header::ChunkFlags};
	///
	/// let chunk = Chunk::new(vec![], ChunkFlags::new(), 1024);
	/// assert_eq!(chunk.size(), 1024);
	/// ```
	pub fn size(&self) -> u64 {
		self.size
	}

	/// Checks the integrity of the chunk data by calculating the appropriate xxhash hash and comparing it with the given hash.
	///
	/// Returns true if the xxhash hash is equal to the hash in the header, otherwise false. 
	///
	/// # Example
	/// ```no_run
	/// use zff::{Chunk, header::ChunkFlags};
	/// use zff::io::calculate_xxhash;
	///
	/// let data = b"test data".to_vec();
	/// let flags = ChunkFlags::new();
	/// let chunk = Chunk::new(data.clone(), flags, data.len() as u64);
	/// let hash = calculate_xxhash(&data);
	/// assert!(chunk.check_integrity(hash).unwrap());
	/// ```
	pub fn check_integrity(&self, original_hash: u64) -> Result<bool> {
		let calculated_hash = calculate_xxhash(&self.data);
		Ok(calculated_hash == original_hash)
	}
}

/// This struct represents a prepared [Chunk] (encrypted and compressed).
#[derive(Debug, Clone, Default)]
pub(crate) struct PreparedChunk {
	pub data: Vec<u8>,
	pub chunk_header: ChunkHeader, // the offset has to be set afterwards
	pub samebytes: Option<u8>,
	pub duplicated: Option<u64>,
}

impl PreparedChunk {
	/// Returns a new [PreparedChunk] with the given values.
	pub fn new(data: Vec<u8>, chunk_header: ChunkHeader, samebytes: Option<u8>, duplicated: Option<u64>) -> PreparedChunk {
		Self {
			data,
			chunk_header,
			samebytes,
			duplicated
		}
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
