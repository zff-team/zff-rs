// - STD
use std::io::{Read, Seek, SeekFrom};

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueDecoder,
	ZffError,
	ZffErrorKind,
	Chunk,
	Encryption,
	Object,
	decompress_buffer,
	header::{SegmentHeader, ObjectHeader, ChunkHeader},
	footer::{SegmentFooter, ObjectFooter},
	ERROR_MISSING_OBJECT_HEADER_IN_SEGMENT,
	ERROR_MISSING_OBJECT_FOOTER_IN_SEGMENT,
};

pub struct Segment<R: Read + Seek> {
	header: SegmentHeader,
	data: R,
	footer: SegmentFooter,
	raw_reader_position: u64,
}

impl<R: Read + Seek> Segment<R> {
	/// creates a new [Segment] by the given values.
	fn new(header: SegmentHeader, data: R, footer: SegmentFooter) -> Segment<R> {
		Self {
			header: header,
			data: data,
			footer: footer,
			raw_reader_position: 0,
		}
	}

	pub fn new_from_reader(mut data: R) -> Result<Segment<R>> {
		let segment_header = SegmentHeader::decode_directly(&mut data)?;

		data.seek(SeekFrom::End(-8))?;
		let footer_offset = u64::decode_directly(&mut data)?;
		data.seek(SeekFrom::Start(footer_offset))?;
		let segment_footer = match SegmentFooter::decode_directly(&mut data) {
			Ok(footer) => footer,
			Err(_) => {
				//if a MainFooter is present...
				data.seek(SeekFrom::Start(footer_offset-8))?;
				let footer_offset = u64::decode_directly(&mut data)?;
				data.seek(SeekFrom::Start(footer_offset))?;
				SegmentFooter::decode_directly(&mut data)?
			},
		};

		Ok(Self::new(segment_header, data, segment_footer))
	}

	pub fn header(&self) -> &SegmentHeader {
		&self.header
	}

	pub fn footer(&self) -> &SegmentFooter {
		&self.footer
	}

	/// Returns the raw chunk, if so present, then also encrypted and/or compressed.
	pub fn raw_chunk(&mut self, chunk_number: u64) -> Result<Chunk> {
		let chunk_offset = match self.footer.chunk_offsets().get(&chunk_number) {
			Some(offset) => offset,
			None => return Err(ZffError::new(ZffErrorKind::DataDecodeChunkNumberNotInSegment, chunk_number.to_string()))
		};
		
		self.data.seek(SeekFrom::Start(*chunk_offset))?;

		Chunk::new_from_reader(&mut self.data)
	}

	/// Returns the chunked data, uncompressed and unencrypted
	pub fn chunk_data(&mut self, chunk_number: u64, object: &Object) -> Result<Vec<u8>> {
		let chunk_offset = match self.footer().chunk_offsets().get(&chunk_number) {
			Some(offset) => offset.clone(),
			None => return Err(ZffError::new(ZffErrorKind::DataDecodeChunkNumberNotInSegment, chunk_number.to_string()))
		};
		
		self.data.seek(SeekFrom::Start(chunk_offset))?;
		let chunk_header = ChunkHeader::decode_directly(&mut self.data)?;
		let chunk_size = chunk_header.chunk_size();
		self.data.seek(SeekFrom::Start(chunk_header.header_size() as u64 + chunk_offset))?;
		
		let mut raw_data_buffer = Vec::with_capacity(*chunk_size as usize);
		self.data.read_exact(&mut raw_data_buffer)?;

		let raw_data_buffer = match object.encryption_algorithm() {
			Some(algo) => {
				match object.encryption_key() {
					Some(encryption_key) => {
						Encryption::decrypt_message(encryption_key, raw_data_buffer, chunk_number, algo)?
					},
					None => raw_data_buffer,
				}
			},
			None => raw_data_buffer,
		};

		if chunk_header.compression_flag() {
			let compression_algorithm = object.header().compression_header().algorithm().clone();
			return decompress_buffer(&raw_data_buffer, compression_algorithm);
		} else {
			return Ok(raw_data_buffer)
		}
		
	}

	pub fn read_object_header(&mut self, object_number: u64) -> Result<ObjectHeader> {
		let offset = match self.footer.object_header_offsets().get(&object_number) {
				Some(value) => value,
				None => return Err(ZffError::new(ZffErrorKind::MalformedSegment, format!("{ERROR_MISSING_OBJECT_HEADER_IN_SEGMENT}{object_number}"))),
		};
		self.data.seek(SeekFrom::Start(*offset))?;
		let object_header = ObjectHeader::decode_directly(&mut self.data)?;
		Ok(object_header)
	}

	pub fn read_encrypted_object_header<P>(&mut self, object_number: u64, decryption_password: P) -> Result<ObjectHeader>
	where
		P: AsRef<[u8]>,
	{
		let offset = match self.footer.object_header_offsets().get(&object_number) {
				Some(value) => value,
				None => return Err(ZffError::new(ZffErrorKind::MalformedSegment, format!("{ERROR_MISSING_OBJECT_HEADER_IN_SEGMENT}{object_number}"))),
		};
		self.data.seek(SeekFrom::Start(*offset))?;
		let object_header = ObjectHeader::decode_encrypted_header_with_password(&mut self.data, decryption_password)?;
		Ok(object_header)
	}

	pub fn read_object_footer(&mut self, object_number: u64) -> Result<ObjectFooter> {
		let offset = match self.footer.object_footer_offsets().get(&object_number) {
			Some(value) => value,
			None => return Err(ZffError::new(ZffErrorKind::MalformedSegment, format!("{ERROR_MISSING_OBJECT_FOOTER_IN_SEGMENT}{object_number}"))),
		};
		self.data.seek(SeekFrom::Start(*offset))?;
		ObjectFooter::decode_directly(&mut self.data)
	}
}

impl<R: Read+Seek> Read for Segment<R> {
	fn read(&mut self, buffer: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
		self.data.seek(SeekFrom::Start(self.raw_reader_position))?;
		let read_bytes = match self.data.read(buffer) {
			Ok(read_bytes) => read_bytes,
			Err(e) => return Err(e)
		};
		self.raw_reader_position += read_bytes as u64;
		Ok(read_bytes)
	}
}

impl<R: Read + Seek> Seek for Segment<R> {
	fn seek(&mut self, seeker: SeekFrom) -> std::result::Result<u64, std::io::Error> {
		let position = self.data.seek(seeker)?;
		self.raw_reader_position = self.data.stream_position()?;
		Ok(position)
	}
}