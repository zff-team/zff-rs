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
	Signature,
	calculate_crc32,
};

use crate::{
	ED25519_DALEK_PUBKEY_LEN,
	ERROR_MISSING_SEGMENT_MAIN_HEADER,
	ERROR_MISSING_SEGMENT_MAIN_FOOTER,
	ERROR_ZFFREADER_MISSING_OBJECT,
	ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION,
	ERROR_ZFFREADER_MISSING_FILE,
	ERROR_ZFFREADER_SEGMENT_NOT_FOUND,
	ERROR_MISMATCH_ZFF_VERSION
};

/// The [ZffReader] can be used to [Read](std::io::Read) (decompressed, decrypted) from given zff-files directly.
pub struct ZffReader<R: Read + Seek> {
	main_header: MainHeader,
	main_footer: MainFooter,
	objects: HashMap<u64, Object>, //<object number, ObjectInformation.
	segments: HashMap<u64, Segment<R>>, //<segment number, Segment-object>, a HashMap is used here instead of a Vec for perfomance reasons.
	chunk_map: HashMap<u64, u64>, //<chunk_number, segment_number> for better runtime performance.
	active_object: u64, // the object number of the active object
	undecryptable_objects: Vec<u64>, // contains all numbers of objects, which could not be decoded, because the appropriate object header is not decryptable with the given password.
}

impl<R: Read + Seek> ZffReader<R> {
	// encryption_passwords: <object number, decryption password>
	/// Creates a new [ZffReader]. The ZffReader needs a [Vec] of [Reader](std::io::Read) of all segments of the zff container 
	/// and a HashMap with the needed decryption passwords.
	pub fn new(raw_segments: Vec<R>, encryption_passwords: HashMap<u64, String>) -> Result<ZffReader<R>> {
		let mut main_header = None;
		let mut main_footer = None;
		let mut segments = HashMap::new();
		let mut chunk_map = HashMap::new();
		let mut undecryptable_objects = Vec::new();
		for mut raw_segment in raw_segments {
			if main_footer.is_none() {
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
				let header = match segment.read_encrypted_object_header(*object_number, encryption_password) {
					Ok(header) => header,
					Err(e) => match e.get_kind() {
						ZffErrorKind::HeaderDecodeEncryptedHeader => segment.read_object_header(*object_number)?,
						_ => return Err(e)
					},
				};
				object_header.insert(object_number, header);
			} else {
				match segment.read_object_header(*object_number) {
					Ok(header) => { object_header.insert(object_number, header); },
					Err(e) => match e.get_kind() {
						ZffErrorKind::HeaderDecodeEncryptedHeader => undecryptable_objects.push(*object_number),
						_ => return Err(e),
					}
				};
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
						ObjectFooter::Physical(footer) => {
							//checks if the first segment is readable (=decrypted)
							let first_chunk_number = footer.first_chunk_number();
							let phy_object = Object::Physical(Box::new(PhysicalObjectInformation::new(header.clone(), footer, encryption_key)));
							let segment = match chunk_map.get(&first_chunk_number) {
								Some(segment_no) => match segments.get_mut(segment_no) {
									Some(segment) => segment,
									None => return Err(ZffError::new(ZffErrorKind::MissingSegment, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
								},
								None => return Err(ZffError::new(ZffErrorKind::MissingSegment, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
							};
							let chunk = segment.raw_chunk(first_chunk_number)?;
							let crc32 = chunk.header().crc32();
							match segment.chunk_data(first_chunk_number, &phy_object) {
								Ok(chunk_data) => {
									if calculate_crc32(&chunk_data) != crc32 && header.encryption_header().is_some() {
										undecryptable_objects.push(*object_number);
									} else {
										objects.insert(*object_number, phy_object);
									}
								},
								Err(e) => match e.get_kind() {
									ZffErrorKind::IoError(_) => {
										undecryptable_objects.push(*object_number);
									},
									_ => return Err(e)
								}
							};
						},
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

							for (file_number, footer) in file_footers.clone() {
								match file_headers.get(&file_number) {
									Some(header) => logical_object.add_file(file_number, File::new(header.clone(), footer)),
									None => return Err(ZffError::new(ZffErrorKind::MissingFileNumber, file_number.to_string())),
								}
							};

							let object = Object::Logical(Box::new(logical_object));
							if let Some(minimum_file_number) = file_footers.keys().min() {
								let first_file_footer = file_footers.get(minimum_file_number).unwrap();
								let first_chunk_number = first_file_footer.first_chunk_number();
								let segment = match chunk_map.get(&first_chunk_number) {
									Some(segment_no) => match segments.get_mut(segment_no) {
										Some(segment) => segment,
										None => return Err(ZffError::new(ZffErrorKind::MissingSegment, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
									},
									None => return Err(ZffError::new(ZffErrorKind::MissingSegment, ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
								};
								let chunk = segment.raw_chunk(first_chunk_number)?;
								let crc32 = chunk.header().crc32();
								match segment.chunk_data(first_chunk_number, &object) {
									Ok(chunk_data) => {
										if calculate_crc32(&chunk_data) == crc32 {
											objects.insert(*object_number, object);
										} else {
											undecryptable_objects.push(*object_number);
										}
									},
									Err(e) => match e.get_kind() {
										ZffErrorKind::IoError(_) => {
											undecryptable_objects.push(*object_number);
										},
										_ => return Err(e),
									}
								};
							}
						},
					}
				},
				None => if !undecryptable_objects.contains(object_number) { return Err(ZffError::new(
					ZffErrorKind::MissingObjectHeaderForPresentObjectFooter, object_number.to_string())) },
			};
		}

		Ok(Self {
			main_header,
			main_footer,
			objects,
			chunk_map,
			segments,
			active_object: 1,
			undecryptable_objects,
		})
	}

	/// returns a list of physical object numbers
	pub fn physical_object_numbers(&self) -> Vec<u64> {
		let mut objects = Vec::new();
		for (object_number, object_information) in &self.objects {
			if let Object::Physical(_) = object_information { objects.push(*object_number) };
		}
		objects
	}

	/// returns a list of logical object numbers
	pub fn logical_object_numbers(&self) -> Vec<u64> {
		let mut objects = Vec::new();
		for (object_number, object_information) in &self.objects {
			if let Object::Logical(_) = object_information { objects.push(*object_number) };
		}
		objects
	}

	/// returns a list of object numbers (physical + logical objects)
	pub fn object_numbers(&self) -> Vec<u64> {
		let mut objects = Vec::new();
		for object_number in self.objects.keys() {
			objects.push(*object_number)
		}
		objects
	}

	/// returns a reference of the appropriate object with the given object number
	pub fn object(&self, object_number: u64) -> Option<&Object> {
		self.objects.get(&object_number)
	}

	/// returns all objects of this reader
	pub fn objects(&self) -> Vec<&Object> {
		let mut objects = Vec::new();
		for object in self.objects.values() {
			objects.push(object)
		}
		objects
	}

	/// returns all numbers of undecryptable objects of this reader
	pub fn undecryptable_objects(&self) -> &Vec<u64> {
		&self.undecryptable_objects
	}

	/// Sets the ZffReader to the given physical object number
	/// # Error
	/// Fails if the given object number not exists, or if the object type of the given object number is a logical object.
	pub fn set_reader_physical_object(&mut self, object_number: u64) -> Result<u64> {
		match self.objects.get(&object_number) {
			Some(Object::Physical(object)) => {
				self.active_object = object_number;
				Ok(object.position())
			},
			Some(Object::Logical(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, object_number.to_string())),
			None => Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string())),
		}
	}

	/// Sets the ZffReader to the given logical object and file number.
	/// # Error
	/// Fails if the given object number not exists,
	/// or if the object type of the given object number is a logical object or the file number not exists in the appropriate object.
	pub fn set_reader_logical_object_file(&mut self, object_number: u64, file_number: u64) -> Result<u64> {
		match self.objects.get_mut(&object_number) {
			Some(Object::Logical(object)) => {
				match object.footer().file_footer_offsets().get(&file_number) {
					Some(_) => {
						self.active_object = object_number;
						object.set_active_file_number(file_number)?;
						Ok(object.position())
					},
					None => Err(ZffError::new(ZffErrorKind::MissingFileNumber, file_number.to_string())),
				}
			},
			Some(Object::Physical(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, object_number.to_string())),
			None => Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string())),
		}
	}

	/// Returns the appropriate file information of the current file.
	/// # Error
	/// Fails if the active object is a physical object.
	pub fn file_information(&self) -> Result<File> {
		match self.objects.get(&self.active_object) {
			Some(Object::Logical(object)) => {
				object.get_active_file()
			},
			Some(Object::Physical(_)) => Err(ZffError::new(ZffErrorKind::MismatchObjectType, &self.active_object.to_string())),
			None => Err(ZffError::new(ZffErrorKind::MissingObjectNumber, &self.active_object.to_string())),
		}
	}

	/// Returns the description notes of the zff container (if available).
	pub fn description_notes(&self) -> Option<&str> {
		self.main_footer.description_notes()
	}

	/// Verifies the signed chunks with the given publickey. Returns a Vec of chunk numbers, which could NOT be verified.
	pub fn verify_chunk_signatures(&mut self, publickey: [u8; ED25519_DALEK_PUBKEY_LEN]) -> Result<Vec<u64>> {
		let current_object = self.object(self.active_object).unwrap().clone(); //unwrap should be safe here.
		match current_object {
			Object::Physical(ref obj_info) => {
				let first_chunk_number = obj_info.footer().first_chunk_number();
				let last_chunk_number = obj_info.footer().first_chunk_number() + obj_info.footer().number_of_chunks() - 1;

				self.verify_chunks(publickey, first_chunk_number, last_chunk_number, &current_object)
			},
			Object::Logical(ref obj_info) => {
				let mut corrupt_chunks = Vec::new();
				for file in obj_info.files().values() {
					let first_chunk_number = file.footer().first_chunk_number();
					let last_chunk_number = file.footer().first_chunk_number() + file.footer().number_of_chunks() - 1;
				
					corrupt_chunks.append(&mut self.verify_chunks(publickey, first_chunk_number, last_chunk_number, &current_object)?);
				}
				Ok(corrupt_chunks)
			},
		}
	}

	fn verify_chunks(&mut self, publickey: [u8; ED25519_DALEK_PUBKEY_LEN], first_chunk_number: u64, last_chunk_number: u64, current_object: &Object) -> Result<Vec<u64>> {
		let mut corrupt_chunks = Vec::new();

		for chunk_number in first_chunk_number..=last_chunk_number {
			let segment_no = self.chunk_map.get_mut(&chunk_number).unwrap();
			let segment = self.segments.get_mut(segment_no).unwrap();

			let chunk_data = segment.chunk_data(chunk_number, current_object)?;
			let signature = match segment.raw_chunk(chunk_number)?.header().signature() {
				Some(signature) => *signature,
				None => return Err(ZffError::new(ZffErrorKind::NoSignatureFoundAtChunk, chunk_number.to_string())),
			};

			if !Signature::verify(publickey, &chunk_data, signature)? {
				corrupt_chunks.push(chunk_number);
			}
		}

		Ok(corrupt_chunks)
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
		let mut current_chunk_number = (first_chunk_number * chunk_size as u64 + object.position()) / chunk_size as u64;
		let mut inner_position = (object.position() % chunk_size as u64) as usize; // the inner chunk position
		let mut read_bytes = 0; // number of bytes which are written to buffer

		loop {
			if read_bytes == buffer.len() || current_chunk_number > last_chunk_number {
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
					error => return Err(std::io::Error::new(std::io::ErrorKind::Other, error.to_string())) 
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
			} else if value >= 0 {
   					object.set_position(object.position() + value as u64);
			} else {
				object.set_position(object.position() - value as u64);
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