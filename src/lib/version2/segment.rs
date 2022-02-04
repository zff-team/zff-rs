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
	header::{SegmentHeader},
	footer::{SegmentFooter},
};

pub struct Segment<R: Read + Seek> {
	header: SegmentHeader,
	data: R,
	footer: SegmentFooter
}

impl<R: Read + Seek> Segment<R> {
	/// creates a new [Segment] by the given values.
	fn new(header: SegmentHeader, data: R, footer: SegmentFooter) -> Segment<R> {
		Self {
			header: header,
			data: data,
			footer: footer,
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
}