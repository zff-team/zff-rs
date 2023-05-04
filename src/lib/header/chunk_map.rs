// - STD
use std::cmp::{PartialEq};
use std::collections::HashMap;
use std::io::{Cursor};

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueEncoder,
	ValueDecoder,
	HEADER_IDENTIFIER_CHUNK_MAP,
	DEFAULT_HEADER_VERSION_CHUNK_MAP,
};

#[derive(Debug,Clone,PartialEq,Eq)]
pub struct ChunkMap {
	pub version: u8,
	pub chunkmap: HashMap<u64, u64>, //<chunk no, offset in segment>
}

impl ChunkMap {
	/// returns a new [ChunkMap] with the given values.
	pub fn new(chunkmap: HashMap<u64, u64>) -> Self {
		Self {
			version: DEFAULT_HEADER_VERSION_CHUNK_MAP,
			chunkmap,
		}
	}

	/// returns a new, empty [ChunkMap] with the given values.
	pub fn new_empty() -> Self {
		Self {
			version: DEFAULT_HEADER_VERSION_CHUNK_MAP,
			chunkmap: HashMap::new(),
		}
	}
}

impl HeaderCoding for ChunkMap {
	type Item = ChunkMap;

	fn identifier() -> u32 {
		HEADER_IDENTIFIER_CHUNK_MAP
	}

	fn version(&self) -> u8 {
		self.version
	}
	
	fn encode_header(&self) -> Vec<u8> {
		let mut vec = Vec::new();

		vec.append(&mut self.version.encode_directly());
		vec.append(&mut self.chunkmap.encode_directly());
		vec
	}

	fn decode_content(data: Vec<u8>) -> Result<Self> {
		let mut cursor = Cursor::new(data);
		let _version = u8::decode_directly(&mut cursor)?; // TODO: return an unsupported header version, if the version does not match with the current version.
		let chunkmap = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
		Ok(Self::new(chunkmap))
	}
}