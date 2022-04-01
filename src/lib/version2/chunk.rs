// - STD
use std::io::{Read};

// - internal
use crate::{
	Result,
	HeaderCoding,
	header::{ChunkHeader},
};

/// This struct represents a full [Chunk], including the appriopriate [crate::header::ChunkHeader] and the chunked data (encoded; compressed and/or encrypted, if set).
pub struct Chunk {
	header: ChunkHeader,
	data: Vec<u8>
}

impl Chunk {
	/// Returns a new [Chunk] with the given values.
	pub fn new(header: ChunkHeader, data: Vec<u8>) -> Chunk {
		Self {
			header: header,
			data: data
		}
	}

	/// Returns a new [Chunk], read from the given [Reader](std::io::Read).
	pub fn new_from_reader<R: Read>(data: &mut R) -> Result<Chunk> {
		let chunk_header = ChunkHeader::decode_directly(data)?;
		let mut chunk_data = Vec::with_capacity(*chunk_header.chunk_size() as usize);
		data.read_exact(& mut chunk_data)?;
		Ok(Self::new(chunk_header, chunk_data))
	}

	/// Returns the underlying [crate::header::ChunkHeader].
	pub fn header(&self) -> &ChunkHeader {
		&self.header
	}

	/// Returns the underlying data.
	pub fn data(&self) -> &Vec<u8> {
		&self.data
	}
}