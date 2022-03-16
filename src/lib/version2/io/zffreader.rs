// - STD
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Cursor};

// - internal
use crate::{
	Result,
	Segment,
	HeaderCoding,
	ValueDecoder,
	ZffError,
	ZffErrorKind,
	header::{MainHeader, FileHeader},
	footer::{MainFooter, ObjectFooter, FileFooter},
	PhysicalObjectInformation,
	LogicalObjectInformation,
	Object,
	File,
};

use crate::{
	ERROR_MISSING_SEGMENT_MAIN_HEADER,
	ERROR_MISSING_SEGMENT_MAIN_FOOTER,
	ERROR_ZFFREADER_MISSING_OBJECT,
	ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION,
	ERROR_ZFFREADER_MISSING_FILE,
	ERROR_ZFFREADER_SEGMENT_NOT_FOUND,
	ERROR_MISMATCH_ZFF_VERSION
};

pub struct ZffReader<R: Read + Seek> {
	main_header: MainHeader,
	main_footer: MainFooter,
	objects: HashMap<u64, Object>, //<object number, ObjectInformation.
	segments: HashMap<u64, Segment<R>>, //<segment number, Segment-object>, a HashMap is used here instead of a Vec for perfomance reasons.
	chunk_map: HashMap<u64, u64>, //<chunk_number, segment_number> for better runtime performance.
	active_object: u64, // the object number of the active object
}

impl<R: Read + Seek> ZffReader<R> {
	// TODO: encrypted segments?
	// encryption_passwords: <object number, decryption password>
	pub fn new(raw_segments: Vec<R>, encryption_passwords: HashMap<u64, Vec<u8>>) -> Result<ZffReader<R>> {
		let mut main_header = None;
		let mut main_footer = None;
		let mut segments = HashMap::new();
		let mut chunk_map = HashMap::new();
		for mut raw_segment in raw_segments {
			if let None = main_footer {
				raw_segment.seek(SeekFrom::End(-8))?;
				let footer_offset = u64::decode_directly(&mut raw_segment)?;
				raw_segment.seek(SeekFrom::Start(footer_offset))?;
				match MainFooter::decode_directly(&mut raw_segment) {
					Ok(mf) => main_footer = Some(mf),
					Err(e) => match e.get_kind() {
						ZffErrorKind::HeaderDecodeMismatchIdentifier => (),
						_ => return Err(e)
					}
				}
				raw_segment.rewind()?;
			};

			if let None = main_header {
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

			for chunk_number in segment.footer().chunk_offsets().keys() {
				chunk_map.insert(*chunk_number, segment.header().segment_number());
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

		let mut object_header = HashMap::new();
		for (object_number, segment_number) in main_footer.object_header() {
			let segment = match segments.get_mut(segment_number) {
				Some(value) => value,
				None => return Err(ZffError::new(ZffErrorKind::MissingSegment, segment_number.to_string())),
			};
			if let Some(encryption_password) = encryption_passwords.get(object_number) {
				let header = segment.read_encrypted_object_header(*object_number, encryption_password)?;
				object_header.insert(object_number, header);
			} else {
				let header = segment.read_object_header(*object_number)?;
				object_header.insert(object_number, header);
			}
		}
		let mut object_footer = HashMap::new();
		for (object_number, segment_number) in main_footer.object_footer() {
			let segment = match segments.get_mut(segment_number) {
				Some(value) => value,
				None => return Err(ZffError::new(ZffErrorKind::MissingSegment, segment_number.to_string())),
			};
			let footer = segment.read_object_footer(*object_number)?;
			object_footer.insert(object_number, footer);
		}

		let mut objects = HashMap::new();
		for (object_number, footer) in object_footer {
			match object_header.get(object_number) {
				Some(header) => {
					let encryption_key = match encryption_passwords.get(object_number) {
						None => None,
						Some(pw) => {
							match header.encryption_header() {
								Some(encryption_header) => Some(encryption_header.decrypt_encryption_key(pw)?),
								None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionHeader, object_number.to_string())),
							}
						},
					};
					match footer {
						ObjectFooter::Physical(footer) => { objects.insert(*object_number, Object::Physical(PhysicalObjectInformation::new(header.clone(), footer, encryption_key))); },
						ObjectFooter::Logical(footer) => {
							let mut logical_object = LogicalObjectInformation::new(header.clone(), footer, encryption_key);
							let mut file_footers = HashMap::new();
							let mut file_headers = HashMap::new();
							for (file_number, segment_number) in logical_object.footer().file_footer_segment_numbers().clone() {
								let segment = match segments.get_mut(&segment_number) {
									Some(value) => value,
									None => return Err(ZffError::new(ZffErrorKind::MissingSegment, segment_number.to_string())),
								};
								let file_footer_offset = match logical_object.footer().file_footer_offsets().get(&file_number) {
									Some(offset) => offset,
									None => return Err(ZffError::new(ZffErrorKind::MalformedSegment, file_number.to_string())),
								};
								segment.seek(SeekFrom::Start(*file_footer_offset))?;
								let file_footer = FileFooter::decode_directly(segment)?;
								file_footers.insert(file_number, file_footer);
							};

							for (file_number, segment_number) in logical_object.footer().file_header_segment_numbers().clone() {
								let segment = match segments.get_mut(&segment_number) {
									Some(value) => value,
									None => return Err(ZffError::new(ZffErrorKind::MissingSegment, segment_number.to_string())),
								};
								let file_header_offset = match logical_object.footer().file_header_offsets().get(&file_number) {
									Some(offset) => offset,
									None => return Err(ZffError::new(ZffErrorKind::MalformedSegment, file_number.to_string())),
								};
								segment.seek(SeekFrom::Start(*file_header_offset))?;
								let file_header = FileHeader::decode_directly(segment)?;
								file_headers.insert(file_number, file_header);
								
							};

							for (file_number, footer) in file_footers {
								match file_headers.get(&file_number) {
									Some(header) => logical_object.add_file(file_number, File::new(header.clone(), footer)),
									None => return Err(ZffError::new(ZffErrorKind::MissingFileNumber, file_number.to_string())),
								}
							};

							let object = Object::Logical(logical_object);
							objects.insert(*object_number, object);
						},
					}
				},
				None => return Err(ZffError::new(ZffErrorKind::MissingObjectHeaderForPresentObjectFooter, object_number.to_string())),
			};
		}

		Ok(Self {
			main_header: main_header,
			main_footer: main_footer,
			objects: objects,
			chunk_map: chunk_map,
			segments: segments,
			active_object: 1,
		})
	}

	/// returns a list of physical object numbers
	pub fn physical_object_numbers(&self) -> Vec<u64> {
		let mut objects = Vec::new();
		for (object_number, object_information) in &self.objects {
			match object_information {
				Object::Physical(_) => objects.push(*object_number),
				_ => ()
			};
		}
		objects
	}

	/// returns a list of logical object numbers
	pub fn logical_object_numbers(&self) -> Vec<u64> {
		let mut objects = Vec::new();
		for (object_number, object_information) in &self.objects {
			match object_information {
				Object::Logical(_) => objects.push(*object_number),
				_ => ()
			};
		}
		objects
	}

	/// returns a list of object numbers (physical + logical objects)
	pub fn object_numbers(&self) -> Vec<u64> {
		let mut objects = Vec::new();
		for (object_number, _) in &self.objects {
			objects.push(*object_number)
		}
		objects
	}

	/// returns a reference of the appropriate object with the given object number
	pub fn object(&self, object_number: u64) -> Option<&Object> {
		self.objects.get(&object_number)
	}

	pub fn set_reader_physical_object(&mut self, object_number: u64) -> Result<u64> {
		match self.objects.get(&object_number) {
			Some(Object::Physical(object)) => {
				self.active_object = object_number;
				return Ok(object.position());
			},
			Some(Object::Logical(_)) => return Err(ZffError::new(ZffErrorKind::MismatchObjectType, object_number.to_string())),
			None => return Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string())),
		};
	}

	pub fn set_reader_logical_object_file(&mut self, object_number: u64, file_number: u64) -> Result<u64> {
		match self.objects.get_mut(&object_number) {
			Some(Object::Logical(object)) => {
				match object.footer().file_footer_offsets().get(&file_number) {
					Some(_) => {
						object.set_active_file_number(file_number)?;
						return Ok(object.position());
					},
					None => return Err(ZffError::new(ZffErrorKind::MissingFileNumber, file_number.to_string())),
				}
			},
			Some(Object::Physical(_)) => return Err(ZffError::new(ZffErrorKind::MismatchObjectType, object_number.to_string())),
			None => return Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string())),
		};
	}

	pub fn file_information(&self) -> Result<File> {
		match self.objects.get(&self.active_object) {
			Some(Object::Logical(object)) => {
				object.get_active_file()
			},
			Some(Object::Physical(_)) => return Err(ZffError::new(ZffErrorKind::MismatchObjectType, &self.active_object.to_string())),
			None => return Err(ZffError::new(ZffErrorKind::MissingObjectNumber, &self.active_object.to_string())),
		}
	}

	pub fn description_notes(&self) -> Option<&str> {
		self.main_footer.description_notes()
	}
}

impl<R: Read + Seek> Read for ZffReader<R> {
	fn read(&mut self, buffer: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
		let object = match self.objects.get_mut(&self.active_object) {
			Some(object) => object,
			None => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{ERROR_ZFFREADER_MISSING_OBJECT}{}", self.active_object)))
		};

		let chunk_size = self.main_header.chunk_size();
		let first_chunk_number = {
			match object {
				Object::Physical(object) => object.footer().first_chunk_number(),
				Object::Logical(object) => match object.get_active_file() {
					Ok(file) => file.footer().first_chunk_number(),
					Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{ERROR_ZFFREADER_MISSING_FILE}{}", object.active_file_number())))
				}
			}
		};
		let last_chunk_number = {
			match object {
				Object::Physical(object) => first_chunk_number + object.footer().number_of_chunks() - 1,
				Object::Logical(object) => match object.get_active_file() {
					Ok(file) => first_chunk_number + file.footer().number_of_chunks() - 1,
					Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{ERROR_ZFFREADER_MISSING_FILE}{}", object.active_file_number())))
				}
			}
		};
		let mut current_chunk_number = ((first_chunk_number * chunk_size as u64))+object.position() / chunk_size as u64;
		let mut inner_position = (object.position() % chunk_size as u64) as usize; // the inner chunk position
		let mut read_bytes = 0; // number of bytes which are written to buffer

		loop {
			if read_bytes == buffer.len() || current_chunk_number >= last_chunk_number {
				break;
			}
			let segment = match self.chunk_map.get(&current_chunk_number) {
				Some(segment_no) => match self.segments.get_mut(segment_no) {
					Some(segment) => segment,
					None => return Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
				},
				None => break,
			};
			let chunk_data = match segment.chunk_data(current_chunk_number, object) {
				Ok(data) => data,
				Err(e) => match e.unwrap_kind() {
					ZffErrorKind::IoError(io_error) => return Err(io_error),
					error @ _ => return Err(std::io::Error::new(std::io::ErrorKind::Other, error.to_string())) 
				},
			};
			let mut cursor = Cursor::new(&chunk_data[inner_position..]);
			read_bytes += cursor.read(&mut buffer[read_bytes..])?;
			inner_position = 0;
			current_chunk_number += 1;
			object.set_position(read_bytes as u64);
		}

		object.set_position(read_bytes as u64);
		Ok(read_bytes)
	}
}


impl<R: Read + Seek> Seek for ZffReader<R> {
	fn seek(&mut self, seek_from: SeekFrom) -> std::result::Result<u64, std::io::Error> {
		let object = match self.objects.get_mut(&self.active_object) {
			Some(object) => object,
			None => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{ERROR_ZFFREADER_MISSING_OBJECT}{}", self.active_object)))
		};
		match seek_from {
			SeekFrom::Start(value) => {
				object.set_position(value);
			},
			SeekFrom::Current(value) => if object.position() as i64 + value < 0 {
				return Err(std::io::Error::new(std::io::ErrorKind::Other, ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))
			} else {
				if value >= 0 {
					object.set_position(object.position() + value as u64);
				} else {
					object.set_position(object.position() - value as u64);
				}
			},
			SeekFrom::End(value) => if object.position() as i64 + value < 0 {
				return Err(std::io::Error::new(std::io::ErrorKind::Other, ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))
			} else {
				let end = {
					match object {
						Object::Physical(object) => object.footer().length_of_data(),
						Object::Logical(object) => {
							match object.get_active_file() {
								Ok(file) => file.length_of_data(),
								Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{ERROR_ZFFREADER_MISSING_FILE}{}", object.active_file_number())))
							}
						},
					}
				};
				if value >= 0 {
					object.set_position(end + value as u64);
				} else {
					object.set_position(end - value as u64);
				}
			},
		}
		Ok(object.position())
	}
}