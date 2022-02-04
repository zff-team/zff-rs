// - STD
use std::io::{Read};

// - internal
use crate::{
	Result,
	HeaderCoding,
	header::{ChunkHeader},
};

pub struct Chunk {
	header: ChunkHeader,
	data: Vec<u8>
}

impl Chunk {
	pub fn new(header: ChunkHeader, data: Vec<u8>) -> Chunk {
		Self {
			header: header,
			data: data
		}
	}

	pub fn new_from_reader<R: Read>(data: &mut R) -> Result<Chunk> {
		let chunk_header = ChunkHeader::decode_directly(data)?;
		let mut chunk_data = Vec::with_capacity(*chunk_header.chunk_size() as usize);
		data.read_exact(& mut chunk_data)?;
		Ok(Self::new(chunk_header, chunk_data))
	}

	pub fn header(&self) -> &ChunkHeader {
		&self.header
	}

	pub fn data(&self) -> &Vec<u8> {
		&self.data
	}
}