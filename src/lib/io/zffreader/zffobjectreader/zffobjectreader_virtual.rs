// - Parent
use super::*;

/// A reader which contains the appropriate metadata of the virtual object 
/// (e.g. the appropriate [ObjectHeader](crate::header::ObjectHeader) and [ObjectFooter](crate::footer::ObjectFooter)).
#[derive(Debug)]
pub(crate) struct ZffObjectReaderVirtual<R: Read + Seek> {
	metadata: ArcZffReaderMetadata<R>,
	/// Contains the appropriate object header
	object_header: ObjectHeader,
	/// Contains the appropriate object footer of the virtual object
	object_footer: ObjectFooterVirtual,
	/// The virtual object map
	virtual_object_map: BTreeSet<BTreeMap<u64, (u64, u64)>>, 
	/// the internal reader position
	position: u64,
}

impl<R: Read + Seek> ZffObjectReaderVirtual<R> {
	/// creates a new [ZffObjectReaderVirtual] with the given metadata.
	pub fn with_data(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Result<Self> {
		let object_header = metadata.object_header(&object_no).unwrap().clone();
		let object_footer = match metadata.object_footer(&object_no) {
			Some(ObjectFooter::Virtual(footer)) => footer.clone(),
			_ => unreachable!(), // already checked before in zffreader::initialize_unencrypted_object_reader();
		};

		let vmi_segment_no = object_footer.virtual_object_map_segment_no;
		let vmi_offset = object_footer.virtual_object_map_offset;

		let virtual_object_map = {
			let mut segments = metadata.segments.write().unwrap();
			let segment = match segments.get_mut(&vmi_segment_no) {
				Some(segment) => segment,
				None => return Err(ZffError::new(
					ZffErrorKind::Missing,
					format!("{ERROR_MISSING_SEGMENT}{vmi_segment_no}"))),
			};
			segment.seek(SeekFrom::Start(vmi_offset))?;
			if let Some(encryption_header) = &object_header.encryption_header {
				let key = match encryption_header.get_encryption_key() {
					Some(key) => key,
					None => return Err(ZffError::new(
						ZffErrorKind::EncryptionError,
						ERROR_MISSING_ENCRYPTION_HEADER_KEY)),
				};
				let enc_info = EncryptionInformation::new(key, encryption_header.algorithm.clone());
				VirtualObjectMap::decode_encrypted_structure_with_key(segment, enc_info, object_no)?
			} else {
				VirtualObjectMap::decode_directly(segment)?
			}
		};

		Ok(Self {
			metadata,
			object_header,
			object_footer,
			virtual_object_map: virtual_object_map.offsetmaps,
			position: 0,
		})
	}

	/// Returns a reference of the appropriate [ObjectHeader](crate::header::ObjectHeader).
	pub fn object_header_ref(&self) -> &ObjectHeader {
		&self.object_header
	}

	/// Returns a reference of the appropriate [crate::footer::ObjectFooterVirtual].
	pub fn object_footer_unwrapped_ref(&self) -> &ObjectFooterVirtual {
		&self.object_footer
	}

	/// Returns the appropriate [ObjectFooter](crate::footer::ObjectFooter).
	pub fn object_footer(&self) -> ObjectFooter {
		ObjectFooter::Virtual(self.object_footer.clone())
	}

}

impl<R: Read + Seek> Read for ZffObjectReaderVirtual<R> {
	fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
		let mut read_bytes = 0; // number of bytes which are written to buffer

		'outer: loop {
			let current_offset = self.position + read_bytes as u64;
			if current_offset >= self.object_footer.length_of_data {
				break;
			}

			// find the appropriate mapping information.
			let virtual_mapping_information = match get_vmi_info(
				&self.virtual_object_map,
				current_offset,
				Arc::clone(&self.metadata)) {
				Ok(mi) => mi,
				Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
			};

			let vmi_obj_no = virtual_mapping_information.object_number;
			let chunk_size = match self.metadata.object_metadata.read().unwrap().get(&vmi_obj_no) {
				Some(ref obj) => obj.header.chunk_size,
				None => return Err(std::io::Error::new(
					std::io::ErrorKind::Other, 
					format!("{ERROR_MISSING_OBJECT_HEADER_IN_SEGMENT}{vmi_obj_no}"))),
			};
			let mut current_chunk_number = virtual_mapping_information.start_chunk_no;
			let mut inner_position = virtual_mapping_information.chunk_offset as usize; // the inner chunk position
			let mut remaining_offset_length = virtual_mapping_information.length as usize;

			loop {
				if read_bytes == buffer.len() {
					break 'outer;
				}

				let chunk_data = if let Some(samebyte) = self.metadata.preloaded_chunkmaps.read().unwrap().get_samebyte(current_chunk_number) {
					vec![samebyte; chunk_size as usize]
				} else {
					get_chunk_data(&vmi_obj_no, Arc::clone(&self.metadata), current_chunk_number)?
				};

				let mut should_break = false;
				let mut cursor = if remaining_offset_length as u64 > chunk_data[inner_position..].len() as u64 {
					Cursor::new(&chunk_data[inner_position..])
				} else {
					should_break = true;
					Cursor::new(&chunk_data[inner_position..remaining_offset_length])
				};
				let read_bytes_at_round = cursor.read(&mut buffer[read_bytes..])?;
				read_bytes += read_bytes_at_round;
				remaining_offset_length -= read_bytes_at_round;
				if should_break {
					break;
				}
				inner_position = 0;
				current_chunk_number += 1;
			}

		}

		self.position += read_bytes as u64;
		Ok(read_bytes)
	}
}

fn get_vmi_info<R: Read + Seek>(
	vmi_map: &BTreeSet<BTreeMap<u64, (u64, u64)>>, 
	offset: u64,
	metadata: ArcZffReaderMetadata<R>) -> Result<VirtualMappingInformation> {
    let (segment_no, offset) = find_vmi_offset(vmi_map, offset).ok_or_else(|| ZffError::new(ZffErrorKind::NotFound, "VMI not found"))?;
    let mut segments = metadata.segments.write().unwrap();
	let segment = match segments.get_mut(&segment_no) {
		Some(segment) => segment,
		None => return Err(ZffError::new(
			ZffErrorKind::Missing, 
			ERROR_ZFFREADER_SEGMENT_NOT_FOUND)),
	};
	segment.seek(SeekFrom::Start(offset))?;
	VirtualMappingInformation::decode_directly(segment)
}

impl<R: Read + Seek> Seek for ZffObjectReaderVirtual<R> {
	fn seek(&mut self, seek_from: SeekFrom) -> std::result::Result<u64, std::io::Error> {
		match seek_from {
			SeekFrom::Start(value) => {
				self.position = value;
			},
			SeekFrom::Current(value) => if self.position as i64 + value < 0 {
				return Err(std::io::Error::new(std::io::ErrorKind::Other, ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))
			} else if value >= 0 {
					self.position += value as u64;
			} else {
				self.position -= value as u64;
			},
			SeekFrom::End(value) => if self.position as i64 + value < 0 {
				return Err(std::io::Error::new(std::io::ErrorKind::Other, ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))
			} else if value >= 0 {
					self.position = self.object_footer.length_of_data + value as u64;
			} else {
				self.position = self.object_footer.length_of_data - value as u64;
			},
		}
		Ok(self.position)
	}
}