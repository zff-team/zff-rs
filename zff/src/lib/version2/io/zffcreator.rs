// - STD
use std::io::{Read, Write, Seek, SeekFrom};

// - internal
use crate::{
	Result,
	HashType,
	HeaderCoding,
	ZffError,
	ZffErrorKind,
	DEFAULT_HEADER_VERSION_SEGMENT_HEADER,
	DEFAULT_FOOTER_VERSION_SEGMENT_FOOTER,
};
use crate::version2::{
	object::{PhysicalObjectEncoder},
	header::{ObjectHeader, MainHeader, SegmentHeader},
	footer::{SegmentFooter},
};

// - external
use ed25519_dalek::{Keypair};

pub struct ZffCreatorPhysical<R: Read> {
	object_encoder: PhysicalObjectEncoder<R>,
	output_filenpath: String,
	current_segment_no: u64,
	current_chunk_no: u64,
	written_object_header: bool,
}

impl<R: Read> ZffCreatorPhysical<R> {
	pub fn new<O: Into<String>>(
		object_header: ObjectHeader,
		input_data: R,
		hash_types: Vec<HashType>,
		encryption_key: Option<Vec<u8>>,
		signature_key: Option<Keypair>,
		main_header: MainHeader,
		output_filenpath: O) -> ZffCreatorPhysical<R> {
		let initial_chunk_number = 1;
		Self {
			object_encoder: PhysicalObjectEncoder::new(
				object_header,
				input_data,
				hash_types,
				encryption_key,
				signature_key,
				main_header,
				initial_chunk_number), // the first chunk number for the first object should always be 1.
			output_filenpath: output_filenpath.into(),
			current_segment_no: 1, // initial segment number should always be 1.
			current_chunk_no: initial_chunk_number, // the initial chunk number should always be 1.
			written_object_header: false,
		}
	}

	fn write_next_segment<W: Write + Seek>(
		&mut self,
		output: &mut W,
		seek_value: u64, // The seek value is a value of bytes you need to skip (e.g. the main_header, the object_header, ...)
		) -> Result<u64> // returns written_bytes
	{
		output.seek(SeekFrom::Start(seek_value))?;
		let mut written_bytes: u64 = 0;
		let target_chunk_size = self.object_encoder.main_header().chunk_size();
		let target_segment_size = self.object_encoder.main_header().segment_size();
		
		//prepare segment header
		let segment_header = SegmentHeader::new(
			DEFAULT_HEADER_VERSION_SEGMENT_HEADER,
			self.object_encoder.main_header().unique_identifier(),
			self.current_segment_no);
		//write segment header
		written_bytes += output.write(&segment_header.encode_directly())? as u64;
		
		//write the object header
		if !self.written_object_header {
			written_bytes += output.write(&self.object_encoder.get_encoded_header())? as u64;
			self.written_object_header = true;
		};

		//prepare segment footer
		let mut segment_footer = SegmentFooter::new_empty(DEFAULT_FOOTER_VERSION_SEGMENT_FOOTER);

		loop {
			if (written_bytes +
				segment_footer.encode_directly().len() as u64 +
				target_chunk_size as u64) > target_segment_size-seek_value as u64 {
				
				if written_bytes == segment_header.encode_directly().len() as u64 {
					return Err(ZffError::new(ZffErrorKind::ReadEOF, ""));
				} else {
					break;
				}
			};
			let chunk_offset = seek_value + written_bytes;
			let chunk = match self.object_encoder.get_next_chunk() {
				Ok(data) => data,
				Err(e) => match e.get_kind() {
					ZffErrorKind::ReadEOF => {
						if written_bytes == segment_header.encode_directly().len() as u64 {
							return Err(e);
						} else {
							break;
						}
					},
					ZffErrorKind::InterruptedInputStream => {
						break;
					},
					_ => return Err(e),
				},
			};
			written_bytes += output.write(&chunk)? as u64;
			segment_footer.add_chunk_offset(chunk_offset);
		}
		segment_footer.set_footer_offset(seek_value + written_bytes);
		segment_footer.set_length_of_segment(seek_value + written_bytes + segment_footer.encode_directly().len() as u64);
		written_bytes += output.write(&segment_footer.encode_directly())? as u64;
		Ok(written_bytes)
	}
}