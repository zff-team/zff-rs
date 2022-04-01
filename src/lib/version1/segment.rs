// - STD
use std::borrow::Borrow;
use std::io::{Read,Seek,SeekFrom};
use std::collections::HashMap;

// - internal
use crate::{
	Result,
	HeaderCoding,
	header::version1::{SegmentHeader, ChunkHeader},
	footer::version1::{SegmentFooter},
	ZffError,
	ZffErrorKind,
	CompressionAlgorithm,
	Encryption,
	EncryptionAlgorithm,
	Signature,
	ED25519_DALEK_PUBKEY_LEN
};

// - external
use zstd;
use lz4_flex;

/// This structure contains a set of methods to operate with a zff segment.
/// The struct contains the [SegmentHeader](crate::header::SegmentHeader) of the segment and the data. The data could be everything which implements [Read] and [Seek].
/// This struct contains also an offset hashmap of all chunks, which are be present in this segment - to jump quickly to the needed data offset.
pub struct Segment<R: Read + Seek> {
	header: SegmentHeader,
	data: R,
	chunk_offsets: HashMap<u64, u64> //<chunk number, offset>
}

impl<R: 'static +  Read + Seek> Segment<R> {
	/// creates a new [Segment] by the given values.
	fn new(header: SegmentHeader, data: R, chunk_offsets: HashMap<u64, u64>) -> Segment<R> {
		Self {
			header,
			data,
			chunk_offsets,
		}
	}

	/// creates a new [Segment] from a given object, which have to implement [Read] and [Seek].
	/// # Example
	/// ```no_run
	/// use std::fs::File;
	/// use zff::Segment;
	/// 
	/// let zff_segment = File::open("zff_file.z01").unwrap();
	/// let segment = Segment::new_from_reader(zff_segment).unwrap();
	/// ```
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

	/// returns the data of the appropriate chunk.
	/// You have to set the chunk_number and the used compression algorithm (the last one can be found in the [MainHeader](crate::header::MainHeader)).
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

		self.data.seek(SeekFrom::Start(chunk_header.header_size() as u64 + *chunk_offset))?;
		let mut chunk_data = Vec::with_capacity(*chunk_size as usize);
		self.data.read_exact(&mut chunk_data)?;
		let mut buffer = Vec::new();
		if !chunk_header.compression_flag() {
			return Ok(chunk_data);
		};
		match compression_algorithm.borrow() {
			CompressionAlgorithm::None => {
				Ok(chunk_data)
			}
			CompressionAlgorithm::Zstd => {
				let mut decoder = zstd::stream::read::Decoder::new(chunk_data.as_slice())?;
				decoder.read_to_end(&mut buffer)?;
				Ok(buffer)
			},
			CompressionAlgorithm::Lz4 => {
				let mut decompressor = lz4_flex::frame::FrameDecoder::new(chunk_data.as_slice());
				decompressor.read_to_end(&mut buffer)?;
				Ok(buffer)
			}
		}
	}

	/// returns the data of the appropriate encrypted chunk.
	/// You have to set the chunk_number and the used compression algorithm,
	/// the decryption key and the encryption algorithm (most parts can be found in the [MainHeader](crate::header::MainHeader)).
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
		
		self.data.seek(SeekFrom::Start(chunk_header.header_size() as u64 + *chunk_offset))?;
		let mut encrypted_data = Vec::with_capacity(*chunk_size as usize);
		self.data.read_exact(&mut encrypted_data)?;
		let decrypted_chunk_data = Encryption::decrypt_message(decryption_key, encrypted_data, chunk_number, encryption_algorithm)?;

		if !chunk_header.compression_flag() {
			return Ok(decrypted_chunk_data);
		};
		match compression_algorithm.borrow() {
			CompressionAlgorithm::None => {
				Ok(decrypted_chunk_data)
			}
			CompressionAlgorithm::Zstd => {
				let mut decompressed_buffer = Vec::new();
				let mut decoder = zstd::stream::read::Decoder::new(decrypted_chunk_data.as_slice())?;
				decoder.read_to_end(&mut decompressed_buffer)?;
				Ok(decompressed_buffer)
			},
			CompressionAlgorithm::Lz4 => {
				let mut decompressed_buffer = Vec::new();
				let mut decompressor = lz4_flex::frame::FrameDecoder::new(decrypted_chunk_data.as_slice());
				decompressor.read_to_end(&mut decompressed_buffer)?;
				Ok(decompressed_buffer)
			}
		}
	}

	/// verifies the ed25519 signature of a specific chunk
	/// returns true if the signature matches the data and false, if the data are corrupt.
	pub fn verify_chunk<C>(&mut self, chunk_number: u64, compression_algorithm: C, publickey: [u8; ED25519_DALEK_PUBKEY_LEN]) -> Result<bool>
	where
		C: Borrow<CompressionAlgorithm>,
	{
		let chunk_data = self.chunk_data(chunk_number, compression_algorithm)?;
		let chunk_offset = match self.chunk_offsets.get(&chunk_number) {
			Some(offset) => offset,
			None => return Err(ZffError::new(ZffErrorKind::DataDecodeChunkNumberNotInSegment, chunk_number.to_string()))
		};
		self.data.seek(SeekFrom::Start(*chunk_offset))?;
		let chunk_header = ChunkHeader::decode_directly(&mut self.data)?;
		let signature = match chunk_header.signature() {
			Some(sig) => sig,
			None => return Err(ZffError::new(ZffErrorKind::NoSignatureFoundAtChunk, "")),
		};
		Signature::verify(publickey, &chunk_data, *signature)
	}

	/// verifies the ed25519 signature of a specific encrypted chunk
	/// returns true if the signature matches the data and false, if the data are corrupt.
	pub fn verify_chunk_decrypted<C, E, K>(
		&mut self,
		chunk_number: u64,
		compression_algorithm: C,
		decryption_key: K, 
		encryption_algorithm: E,
		publickey: [u8; ED25519_DALEK_PUBKEY_LEN]) -> Result<bool>
	where
		C: Borrow<CompressionAlgorithm>,
		K: AsRef<[u8]>,
		E: Borrow<EncryptionAlgorithm>,
	{
		let chunk_data = self.chunk_data_decrypted(chunk_number, compression_algorithm, decryption_key, encryption_algorithm)?;
		let chunk_offset = match self.chunk_offsets.get(&chunk_number) {
			Some(offset) => offset,
			None => return Err(ZffError::new(ZffErrorKind::DataDecodeChunkNumberNotInSegment, chunk_number.to_string()))
		};
		self.data.seek(SeekFrom::Start(*chunk_offset))?;
		let chunk_header = ChunkHeader::decode_directly(&mut self.data)?;
		let signature = match chunk_header.signature() {
			Some(sig) => sig,
			None => return Err(ZffError::new(ZffErrorKind::NoSignatureFoundAtChunk, "")),
		};
		Signature::verify(publickey, &chunk_data, *signature)
	}

	/// returns a reference to the inner [SegmentHeader](crate::header::SegmentHeader).
	pub fn header(&self) -> &SegmentHeader {
		&self.header
	}

	/// returns a reference to the chunk offset hashmap.
	pub fn chunk_offsets(&self) -> &HashMap<u64, u64> {
		&self.chunk_offsets
	}

	/// returns a reference to underlying value.
	pub fn data(&self) -> &R {
		&self.data
	}
}