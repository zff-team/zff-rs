// - Parent
use super::*;

/// A reader which contains the appropriate metadata of a physical object 
/// (e.g. the appropriate [ObjectHeader](crate::header::ObjectHeader) and [ObjectFooter](crate::footer::ObjectFooter)).
#[derive(Debug)]
pub(crate) struct ZffObjectReaderPhysical<R: Read + Seek> {
	metadata: ArcZffReaderMetadata<R>,
	object_header: ObjectHeader,
	object_footer: ObjectFooterPhysical,
	position: u64
}

impl<R: Read + Seek> ZffObjectReaderPhysical<R> {
	/// creates a new [ZffObjectReaderPhysical] with the given metadata.
	pub fn with_metadata(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Self {
		let object_header = metadata.object_header(&object_no).unwrap().clone();
		let object_footer = match metadata.object_footer(&object_no) {
			Some(ObjectFooter::Physical(footer)) => footer.clone(),
			_ => unreachable!(), // already checked before in zffreader::initialize_unencrypted_object_reader();
		};
		Self {
			metadata,
			object_header,
  			object_footer,
			position: 0
		}
	}

	/// Returns a reference to the [ObjectHeader](crate::header::ObjectHeader).
	pub fn object_header_ref(&self) -> &ObjectHeader {
		&self.object_header
	}

	/// Returns the appropriate [ObjectFooter](crate::footer::ObjectFooter).
	pub fn object_footer(&self) -> ObjectFooter {
		ObjectFooter::Physical(self.object_footer.clone())
	}

	/// Returns the unwrapped object footer
	pub fn object_footer_unwrapped_ref(&self) -> &ObjectFooterPhysical {
		&self.object_footer
	}
}

impl<R: Read + Seek> Read for ZffObjectReaderPhysical<R> {
	fn read(&mut self, buffer: &mut [u8], ) -> std::io::Result<usize> {
		let chunk_size = self.object_header.chunk_size;
		let first_chunk_number = self.object_footer.first_chunk_number;
		let last_chunk_number = first_chunk_number + self.object_footer.number_of_chunks - 1;
		let mut current_chunk_number = (first_chunk_number * chunk_size + self.position) / chunk_size;
		let mut inner_position = (self.position % chunk_size) as usize; // the inner chunk position
		let mut read_bytes = 0; // number of bytes which are written to buffer

		loop {
			if read_bytes == buffer.len() || current_chunk_number > last_chunk_number {
				break;
			}

			let chunk_data = if let Some(samebyte) = self.metadata.preloaded_chunkmaps.read().unwrap().get_samebyte(current_chunk_number) {
				vec![samebyte; chunk_size as usize]
			} else {
				let object_no = &self.object_header.object_number;
				get_chunk_data(object_no, Arc::clone(&self.metadata), current_chunk_number)?
			};
			let mut cursor = Cursor::new(&chunk_data[inner_position..]);
			read_bytes += cursor.read(&mut buffer[read_bytes..])?;
			inner_position = 0;
			current_chunk_number += 1;
		}

		self.position += read_bytes as u64;
		Ok(read_bytes)
	}
}

impl<R: Read + Seek> Seek for ZffObjectReaderPhysical<R> {
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
