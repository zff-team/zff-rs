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
};

use crate::{
	ERROR_MISSING_SEGMENT_MAIN_HEADER,
	ERROR_MISSING_SEGMENT_MAIN_FOOTER,
	ERROR_MISMATCH_ZFF_VERSION
};

/// The [ZffMetadataReader] provide some methods to gain information about the underlying zff container.
pub struct ZffMetadataReader<R: Read + Seek> {
	main_header: MainHeader,
	main_footer: MainFooter,
	segments: HashMap<u64, Segment<R>>, //<segment number, Segment-object>, a HashMap is used here instead of a Vec for perfomance reasons.
}

impl<R: Read + Seek> ZffMetadataReader<R> {
	pub fn new(raw_segments: Vec<R>) -> Result<ZffMetadataReader<R>> {
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

		Ok(Self {
			main_header,
			main_footer,
			segments
		})

	}

	/// returns a list of object numbers (physical + logical objects)
	pub fn object_numbers(&self) -> Vec<u64> {
		self.main_footer.object_header().keys().copied().collect()
	}

	/// returns a list of encrypted object numbers
	pub fn encrypted_object_numbers(&mut self) -> Result<Vec<u64>> {
		let mut encrypted_object_numbers = Vec::new();
		for (object_number, segment_number) in self.main_footer.object_header() {
			let segment = match self.segments.get_mut(segment_number) {
				Some(s) => s,
				None => return Err(ZffError::new(ZffErrorKind::MissingSegment, segment_number.to_string())),
			};
			match objectstate(segment, *object_number) {
				Ok(obj_state) => if obj_state != ObjectState::Unencrypted { encrypted_object_numbers.push(*object_number) },
				Err(e) => return Err(e),
			}
		}
		Ok(encrypted_object_numbers)
	}

	/// returns a list of physical object numbers
	pub fn physical_object_numbers(&mut self) -> Result<Vec<u64>> {
		let mut object_numbers = Vec::new();
		for (object_number, segment_number) in self.main_footer.object_footer() {
			let segment = match self.segments.get_mut(segment_number) {
				Some(s) => s,
				None => return Err(ZffError::new(ZffErrorKind::MissingSegment, segment_number.to_string())),
			};
			match segment.read_object_footer(*object_number) {
				Ok(obj_footer) => if let ObjectFooter::Physical(_) = obj_footer { object_numbers.push(*object_number) },
				Err(e) => return Err(e)
			}
		}
		Ok(object_numbers)
	}

	/// returns a list of logical object numbers
	pub fn logical_object_numbers(&mut self) -> Result<Vec<u64>> {
		let mut object_numbers = Vec::new();
		for (object_number, segment_number) in self.main_footer.object_footer() {
			let segment = match self.segments.get_mut(segment_number) {
				Some(s) => s,
				None => return Err(ZffError::new(ZffErrorKind::MissingSegment, segment_number.to_string())),
			};
			match segment.read_object_footer(*object_number) {
				Ok(obj_footer) => if let ObjectFooter::Logical(_) = obj_footer { object_numbers.push(*object_number) },
				Err(e) => return Err(e)
			}
		}
		Ok(object_numbers)
	}

	/// Returns the description notes of the zff container (if available).
	pub fn description_notes(&self) -> Option<&str> {
		self.main_footer.description_notes()
	}

	/// Returns a reference of the [MainHeader]
	pub fn main_header(&self) -> &MainHeader {
		&self.main_header
	}

	/// Returns a reference of the [MainFooter]
	pub fn main_footer(&self) -> &MainFooter {
		&self.main_footer
	}

}

fn find_mainfooter<R: Read + Seek>(data: &mut R) -> Result<MainFooter> {
	data.seek(SeekFrom::End(-8))?;
	let footer_offset = u64::decode_directly(data)?;
	data.seek(SeekFrom::Start(footer_offset))?;
	match MainFooter::decode_directly(data) {
		Ok(mf) => {
			data.rewind()?;
			Ok(mf)
		},
		Err(e) => match e.get_kind() {
			ZffErrorKind::HeaderDecodeMismatchIdentifier => {
				data.rewind()?;
				Err(ZffError::new(ZffErrorKind::Custom, ERROR_MISSING_SEGMENT_MAIN_FOOTER))
			},
			_ => Err(e)
		}
	}
}

fn objectstate<R: Read + Seek>(segment: &mut Segment<R>, object_number: u64) -> Result<ObjectState> {
	let obj_header = match segment.read_object_header(object_number) {
		Ok(header) => header,
		Err(e) => match e.get_kind() {
			ZffErrorKind::HeaderDecodeEncryptedHeader => return Ok(ObjectState::EncryptedHeader),
			_ => return Err(e),
		}
	};
	if obj_header.encryption_header().is_some() {
		Ok(ObjectState::EncryptedData)
	} else {
		Ok(ObjectState::Unencrypted)
	}
}

#[derive(PartialEq)]
enum ObjectState {
	Unencrypted,
	EncryptedData,
	EncryptedHeader,
}