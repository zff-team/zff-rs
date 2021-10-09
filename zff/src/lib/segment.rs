// - STD
use std::borrow::Borrow;
use std::io::{Read,Seek,SeekFrom};
use std::collections::HashMap;

// - internal
use crate::{
	Result,
	HeaderCoding,
	header::{SegmentHeader, ChunkHeader},
	footer::{SegmentFooter},
	ValueDecoder,
	ZffError,
	ZffErrorKind,
	CompressionAlgorithm,
	Encryption,
	EncryptionAlgorithm,
};

// - external
use slice::IoSlice;
use zstd;
use lz4_flex;

//
pub struct Segment<R: Read + Seek> {
	header: SegmentHeader,
	data: R,
	chunk_offsets: HashMap<u64, u64> //<chunk number, offset>
}

impl<R: 'static +  Read + Seek> Segment<R> {
	fn new(header: SegmentHeader, data: R, chunk_offsets: HashMap<u64, u64>) -> Segment<R> {
		Self {
			header: header,
			data: data,
			chunk_offsets: chunk_offsets,
		}
	}

	pub fn new_from_reader(mut data: R) -> Result<Segment<R>> {
		let stream_position = data.stream_position()?; //uses the current stream position. This is important for the first segment (which contains a main header);
		let segment_header = SegmentHeader::decode_directly(&mut data)?;
		let footer_offset = segment_header.footer_offset();
		let initial_chunk_header = ChunkHeader::decode_directly(&mut data)?;
		let initial_chunk_number = initial_chunk_header.chunk_number();
		data.seek(SeekFrom::Start(footer_offset))?;
		let segment_footer = SegmentFooter::decode_directly(&mut data)?;
		let mut chunk_offsets = HashMap::new();
		let mut chunk_number = initial_chunk_number;
		for offset in segment_footer.chunk_offsets() {
			chunk_offsets.insert(chunk_number, *offset);
			chunk_number += 1;
		}
		data.seek(SeekFrom::Start(stream_position))?;
		let _ = SegmentHeader::decode_directly(&mut data)?;
		Ok(Self::new(segment_header, data, chunk_offsets))
	}

	pub fn chunk_data<C>(&mut self, chunk_number: u64, compression_algorithm: C) -> Result<Vec<u8>>
	where
		C: Borrow<CompressionAlgorithm>,
	{
		let chunk_offset = match self.chunk_offsets.get(&chunk_number) {
			Some(offset) => offset,
			None => return Err(ZffError::new(ZffErrorKind::DataDecodeChunkNumberNotInSegment, chunk_number.to_string()))
		};
		self.data.seek(SeekFrom::Start(*chunk_offset))?;
		let chunk_header = ChunkHeader::decode_directly(&mut self.data)?;
		let chunk_size = chunk_header.chunk_size();
		let bytes_to_skip = chunk_header.header_size() as u64 + *chunk_offset;
		let mut chunk_data = IoSlice::new(self.data.by_ref(), bytes_to_skip, *chunk_size)?;
		let mut buffer = Vec::new();
		match compression_algorithm.borrow() {
			CompressionAlgorithm::None => {
				chunk_data.read_to_end(&mut buffer)?;
				return Ok(buffer);
			}
			CompressionAlgorithm::Zstd => {
				let mut decoder = zstd::stream::read::Decoder::new(chunk_data)?;
				decoder.read_to_end(&mut buffer)?;
				return Ok(buffer);
			},
			CompressionAlgorithm::Lz4 => {
				let mut decompressor = lz4_flex::frame::FrameDecoder::new(chunk_data);
				decompressor.read_to_end(&mut buffer)?;
				return Ok(buffer);
			}
		}
	}

	pub fn chunk_data_decrypted<C, K, E>(
		&mut self, 
		chunk_number: u64, 
		compression_algorithm: C, 
		decryption_key: K, 
		encryption_algorithm: E) -> Result<Vec<u8>>
	where
		C: Borrow<CompressionAlgorithm>,
		K: AsRef<[u8]>,
		E: Borrow<EncryptionAlgorithm>,
	{
		let chunk_offset = match self.chunk_offsets.get(&chunk_number) {
			Some(offset) => offset,
			None => return Err(ZffError::new(ZffErrorKind::DataDecodeChunkNumberNotInSegment, chunk_number.to_string()))
		};
		self.data.seek(SeekFrom::Start(*chunk_offset))?;
		let chunk_header = ChunkHeader::decode_directly(&mut self.data)?;
		let chunk_size = chunk_header.chunk_size();
		let bytes_to_skip = chunk_header.header_size() as u64 + *chunk_offset;
		let mut encrypted_data = IoSlice::new(self.data.by_ref(), bytes_to_skip, *chunk_size)?;
		let mut buffer = Vec::new();
		encrypted_data.read_to_end(&mut buffer)?;
		let decrypted_chunk_data = Encryption::decrypt_message(decryption_key, buffer, chunk_number, encryption_algorithm)?;
		match compression_algorithm.borrow() {
			CompressionAlgorithm::None => {
				return Ok(decrypted_chunk_data);
			}
			CompressionAlgorithm::Zstd => {
				let mut decompressed_buffer = Vec::new();
				let mut decoder = zstd::stream::read::Decoder::new(decrypted_chunk_data.as_slice())?;
				decoder.read_to_end(&mut decompressed_buffer)?;
				return Ok(decompressed_buffer);
			},
			CompressionAlgorithm::Lz4 => {
				let mut decompressed_buffer = Vec::new();
				let mut decompressor = lz4_flex::frame::FrameDecoder::new(decrypted_chunk_data.as_slice());
				decompressor.read_to_end(&mut decompressed_buffer)?;
				return Ok(decompressed_buffer);
			}
		}
	}

	pub fn header(&self) -> &SegmentHeader {
		&self.header
	}

	pub fn chunk_offsets(&self) -> &HashMap<u64, u64> {
		&self.chunk_offsets
	}

	pub fn data(&self) -> &R {
		&self.data
	}
}