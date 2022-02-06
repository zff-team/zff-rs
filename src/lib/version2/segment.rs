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
	header::{SegmentHeader, ObjectHeader},
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
	pub fn raw_chunk(&mut self, chunk_no: u64) -> Result<Chunk> {
		let chunk_offset = match self.footer.chunk_offsets().get(&chunk_no) {
			Some(offset) => offset,
			None => return Err(ZffError::new(ZffErrorKind::DataDecodeChunkNumberNotInSegment, chunk_no.to_string()))
		};
		
		self.data.seek(SeekFrom::Start(*chunk_offset))?;

		Chunk::new_from_reader(&mut self.data)
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