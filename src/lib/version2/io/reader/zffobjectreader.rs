// - STD
use std::io::{Read, Seek, SeekFrom};
use std::collections::HashMap;

// - internal
use crate::{
	Result,
	Segment,
	HeaderCoding,
	ValueDecoder,
	ZffError,
	ZffErrorKind,
	header::{MainHeader},
	footer::{MainFooter, ObjectFooter},
	Object,
};

use crate::{
	ERROR_MISSING_SEGMENT_MAIN_HEADER,
	ERROR_MISSING_SEGMENT_MAIN_FOOTER,
	ERROR_MISMATCH_ZFF_VERSION
};

use super::*;

/// The ZffObjectReader implements io::Read and additional operations for a single zff-Object.
pub struct ZffObjectReader<R: Read + Seek> {
	object: Object,
	segments: HashMap<u64, Segment<R>>, //<segment number, Segment-object> - this HashMap contains only the segments which contain the header/footer of the object and the appropriate chunks.
	chunk_map: Option<HashMap<u64, u64>>, //optional loading of chunkmap into RAM.
}

impl<R: Read + Seek> ZffObjectReader<R> {

	/// Returns a new ZffObjectReader by the given parameter.
	pub fn new<S: Into<String>>(
		raw_segments: Vec<R>,
		decryption_password: Option<S>,
		object_number: u64,
		) -> Result<ZffObjectReader<R>> 
	{
		let mut main_header = None;
		let mut main_footer = None;
		let mut segments = HashMap::new();

		for mut raw_segment in raw_segments {

			if main_footer.is_none() {
				if let Ok(mf) = find_mainfooter(&mut raw_segment) { main_footer = Some(mf) }
			};

			if main_header.is_none() {
				match MainHeader::decode_directly(&mut raw_segment) {
					Ok(mh) => {
						match mh.version() {
							2 => main_header = Some(mh),
							_ => return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_MISMATCH_ZFF_VERSION)),
						}
						
					},
					Err(e) => match e.get_kind() {
						ZffErrorKind::HeaderDecodeMismatchIdentifier => raw_segment.rewind()?,
						_ => return Err(e),
					}
				}
			};

			let segment = Segment::new_from_reader(raw_segment)?;
			match segment.header().version() {
				2 => (),
				_ => return Err(ZffError::new(ZffErrorKind::HeaderDecodeMismatchIdentifier, ERROR_MISMATCH_ZFF_VERSION)),
			}

			segments.insert(segment.header().segment_number(), segment);
		}

		let main_header = match main_header {
			Some(mh) => mh,
			None => return Err(ZffError::new(ZffErrorKind::MissingSegment, ERROR_MISSING_SEGMENT_MAIN_HEADER))
		};
		let main_footer = match main_footer {
			Some(mf) => mf,
			None => return Err(ZffError::new(ZffErrorKind::MissingSegment, ERROR_MISSING_SEGMENT_MAIN_FOOTER))
		};

		let object = get_object(&mut segments, &main_footer, decryption_password, object_number)?;

		unimplemented!()
	}	
}