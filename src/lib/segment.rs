// - STD
use core::borrow::Borrow;
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueDecoder,
	ZffError,
	ZffErrorKind,
	Encryption,
	CompressionAlgorithm,
	ChunkContent,
	decompress_buffer,
	header::{SegmentHeader, ObjectHeader, EncryptionInformation, EncryptedObjectHeader, ChunkFlags},
	footer::{SegmentFooter, ObjectFooter, EncryptedObjectFooter},
	constants::*,
};

// - external
#[cfg(feature = "log")]
use log::trace;

/// Represents a full [Segment]
/// 
/// The [Segment] struct contains a [crate::header::SegmentHeader],
/// a [crate::footer::SegmentFooter], a [Read](std::io::Read)er to the appropriate
/// segmented data and a position marker for this [Read](std::io::Read)er.
#[derive(Debug)]
pub struct Segment<R: Read + Seek> {
	header: SegmentHeader,
	data: R,
	footer: SegmentFooter,
	raw_reader_position: u64,
}

impl<R: Read + Seek> Segment<R> {
	/// creates a new [Segment] by the given values.
	pub fn with_header_and_data(header: SegmentHeader, data: R, footer: SegmentFooter) -> Segment<R> {
		Self {
			header,
			data,
			footer,
			raw_reader_position: 0,
		}
	}

	/// Creates a new [Segment] from the given [Read](std::io::Read)er.
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

		Ok(Self::with_header_and_data(segment_header, data, segment_footer))
	}

	/// Returns a reference to the underlying [crate::header::SegmentHeader].
	pub fn header(&self) -> &SegmentHeader {
		&self.header
	}

	/// Returns a reference to the underlying [crate::footer::SegmentFooter].
	pub fn footer(&self) -> &SegmentFooter {
		&self.footer
	}

	// calculates the offset of the appropriate chunk header.
	fn calc_seek_offset_chunk_header(&self, chunk_number: u64) -> Result<u64> {
		let chunkmap_offset = get_chunkmap_offset(&self.footer.chunk_header_map_table, chunk_number)?;
		//get the first chunk number of the specific chunk map
		let first_chunk_number_of_map = get_first_chunknumber(
			&self.footer.chunk_header_map_table, chunk_number, self.footer.first_chunk_number)?;

		// skips the chunk map header and the other chunk entries.
		let seek_offset = chunkmap_offset + // go to the appropriate chunkmap
					      DEFAULT_LENGTH_HEADER_IDENTIFIER as u64 + //skip the chunk header identifier 
						  DEFAULT_LENGTH_VALUE_HEADER_LENGTH as u64 + //skip the header length value
						  1 + // skip the ChunkMap header version
						  8 + // skip the length of the map
						  ((chunk_number - first_chunk_number_of_map) * (8 + 38)) +//skip the other chunk entries
						  8; // skip the chunk number itself
		Ok(seek_offset)
	}

	/// Returns the offset of the appropriate chunk (number).
	pub fn get_chunk_offset(&mut self, chunk_number: &u64) -> Result<u64> {
		let chunk_header_offset = self.calc_seek_offset_chunk_header(*chunk_number)?;
		let seek_offset = chunk_header_offset + // go to the appropriate chunk header
						  4 + // skip the magic bytes
						  8 + // skip the header length
						  1;

		//go to the appropriate chunk map.
		self.data.seek(SeekFrom::Start(seek_offset))?;
		// read the appropriate offset
		let offset = u64::decode_directly(&mut self.data)?;
		Ok(offset)
	}

	/// Returns the size of the appropriate (encrypted, compressed, ...) chunk (number)
	pub fn get_chunk_size(&mut self, chunk_number: &u64) -> Result<u64> {
		let chunk_header_offset = self.calc_seek_offset_chunk_header(*chunk_number)?;
		let seek_offset = chunk_header_offset + // go to the appropriate chunk header
						  4 + // skip the magic bytes
						  8 + // skip the header length
						  1 + // skip the chunk type
						  8; // skip the chunk offset

		//go to the appropriate chunk map.
		self.data.seek(SeekFrom::Start(seek_offset))?;
		// read the appropriate offset
		let size = u64::decode_directly(&mut self.data)?;
		Ok(size)
	}

	/// Returns the flags of the appropriate (encrypted, compressed, ...) chunk (number)
	pub fn get_chunk_flags(&mut self, chunk_number: &u64) -> Result<ChunkFlags> {
		let chunk_header_offset = self.calc_seek_offset_chunk_header(*chunk_number)?;
		let seek_offset = chunk_header_offset + // go to the appropriate chunk header
						  4 + // skip the magic bytes
						  8 + // skip the header length
						  1 + // skip the chunk type
						  8 + // skip the chunk offset
						  8; // skip the chunk size

		//go to the appropriate chunk map.
		self.data.seek(SeekFrom::Start(seek_offset))?;
		// read the appropriate offset
		let flags = ChunkFlags::decode_directly(&mut self.data)?;
		Ok(flags)
	}
	
	/// Returns the chunked data, uncompressed and unencrypted.
	/// Chunk metadata could be optionally attached, e.g. from a precached chunk map.
	pub(crate) fn chunk_data<E, C>(&mut self, 
		chunk_number: u64, 
		encryption_information: &Option<E>, 
		compression_algorithm: C,
		chunk_offset: Option<u64>,
		chunk_size: Option<u64>,
		flags: Option<ChunkFlags>,) -> Result<ChunkContent>
	where
		E: Borrow<EncryptionInformation>,
		C: Borrow<CompressionAlgorithm>,
	{
		let chunk_offset = match chunk_offset {
			None => self.get_chunk_offset(&chunk_number)?,
			Some(offset) => offset
		};
		let chunk_size = match chunk_size {
			None => self.get_chunk_size(&chunk_number)?,
			Some(size) => size
		};
		let flags = match flags {
			None => self.get_chunk_flags(&chunk_number)?,
			Some(flags) => flags
		};


		self.data.seek(SeekFrom::Start(chunk_offset))?;

		let mut raw_data_buffer = vec![0u8; chunk_size as usize];
		self.data.read_exact(&mut raw_data_buffer)?;

		if let Some(enc_info) = encryption_information {
			let enc_info = enc_info.borrow();
			raw_data_buffer = Vec::<u8>::decrypt(
				&enc_info.encryption_key, 
				raw_data_buffer, 
				chunk_number, 
				&enc_info.algorithm)?;
		}
		let chunk_content = if flags.compression {
			decompress_buffer(&raw_data_buffer, compression_algorithm.borrow())?
		} else {
			raw_data_buffer
		};

		if flags.same_bytes {
			let single_byte = match chunk_content.first() {
				Some(data) => data,
				None => return Err(ZffError::new(ZffErrorKind::Invalid, ERROR_COULD_NOT_FIND_EXPECTED_SAMEBYTE)),
			};
			Ok(ChunkContent::SameBytes(*single_byte))
		} else if flags.duplicate {
			let mut arr: [u8; 8] = Default::default();
			arr.copy_from_slice(&chunk_content);
			Ok(ChunkContent::Duplicate(u64::from_le_bytes(arr)))
		} else {
			Ok(ChunkContent::Raw(chunk_content))
		}
	}

	/// Returns the [crate::header::ObjectHeader] of the given object number, if available in this [Segment]. Otherwise, returns an error.
	pub fn read_object_header(&mut self, object_number: u64) -> Result<ObjectHeader> {
		let offset = match self.footer.object_header_offsets().get(&object_number) {
				Some(value) => value,
				None => return Err(ZffError::new(ZffErrorKind::NotFound, format!("{ERROR_MISSING_OBJECT_HEADER_IN_SEGMENT}{object_number}"))),
		};
		self.data.seek(SeekFrom::Start(*offset))?;

		#[cfg(feature = "log")]
		trace!("Initialize object header for object {object_number} at offset {offset} in segment {}", self.header().segment_number);

		let object_header = ObjectHeader::decode_directly(&mut self.data)?;
		Ok(object_header)
	}

	/// Returns the [EncryptedObjectHeader] of the given object number (if available in this [Segment]). Otherwise, returns an error.
	pub fn read_encrypted_object_header(&mut self, object_number: u64) -> Result<EncryptedObjectHeader> {
		let offset = match self.footer.object_header_offsets().get(&object_number) {
				Some(value) => value,
				None => return Err(ZffError::new(ZffErrorKind::NotFound, format!("{ERROR_MISSING_OBJECT_HEADER_IN_SEGMENT}{object_number}"))),
		};
		self.data.seek(SeekFrom::Start(*offset))?;
		let object_header = EncryptedObjectHeader::decode_directly(&mut self.data)?;
		Ok(object_header)
	}

	/// Returns the [crate::header::ObjectHeader] of the given object number (decrypts the encrypted object header on-the-fly with the given decryption password).
	/// # Error
	/// Fails if the [crate::header::ObjectHeader] could not be found in this [Segment] or/and if the decryption password is wrong.
	pub fn read_and_decrypt_object_header<P>(&mut self, object_number: u64, decryption_password: P) -> Result<ObjectHeader>
	where
		P: AsRef<[u8]>,
	{
		let offset = match self.footer.object_header_offsets().get(&object_number) {
				Some(value) => value,
				None => return Err(ZffError::new(ZffErrorKind::NotFound, format!("{ERROR_MISSING_OBJECT_HEADER_IN_SEGMENT}{object_number}"))),
		};
		self.data.seek(SeekFrom::Start(*offset))?;
		let object_header = ObjectHeader::decode_encrypted_header_with_password(&mut self.data, decryption_password)?;
		Ok(object_header)
	}

	/// Returns the [crate::footer::ObjectFooter] of the given object number, if available in this [Segment]. Otherwise, returns an error.
	pub fn read_object_footer(&mut self, object_number: u64) -> Result<ObjectFooter> {
		let offset = match self.footer.object_footer_offsets().get(&object_number) {
			Some(value) => value,
			None => return Err(ZffError::new(ZffErrorKind::NotFound, format!("{ERROR_MISSING_OBJECT_FOOTER_IN_SEGMENT}{object_number}"))),
		};
		self.data.seek(SeekFrom::Start(*offset))?;
		
		#[cfg(feature = "log")]
		trace!("Initialize object footer for object {object_number} at offset {offset} in segment {}", self.header().segment_number);
		
		ObjectFooter::decode_directly(&mut self.data)
	}

	/// Returns the [crate::footer::EncryptedObjectFooter] of the given object number, if available in this [Segment]. Otherwise, returns an error.
	pub fn read_encrypted_object_footer(&mut self, object_number: u64) -> Result<EncryptedObjectFooter> {
		let offset = match self.footer.object_footer_offsets().get(&object_number) {
				Some(value) => value,
				None => return Err(ZffError::new(ZffErrorKind::NotFound, format!("{ERROR_MISSING_OBJECT_FOOTER_IN_SEGMENT}{object_number}"))),
		};
		self.data.seek(SeekFrom::Start(*offset))?;
		let encrypted_object_footer = EncryptedObjectFooter::decode_directly(&mut self.data)?;
		Ok(encrypted_object_footer)
	}

	/// Returns the [crate::footer::ObjectFooter] of the given object number (decrypts the encrypted object footer on-the-fly with the given decryption password).
	/// # Error
	/// Fails if the [crate::footer::ObjectFooter] could not be found in this [Segment] or/and if the decryption password is wrong.
	pub fn read_and_decrypt_object_footer<E>(&mut self, object_number: u64, encryption_information: E) -> Result<ObjectFooter>
	where
		E: Borrow<EncryptionInformation>,
	{
		let offset = match self.footer.object_footer_offsets().get(&object_number) {
				Some(value) => value,
				None => return Err(ZffError::new(ZffErrorKind::NotFound, format!("{ERROR_MISSING_OBJECT_FOOTER_IN_SEGMENT}{object_number}"))),
		};
		self.data.seek(SeekFrom::Start(*offset))?;
		let encrypted_object_footer = EncryptedObjectFooter::decode_directly(&mut self.data)?;
		let enc_info = encryption_information.borrow();
		encrypted_object_footer.decrypt_and_consume(&enc_info.encryption_key, &enc_info.algorithm)
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

fn get_chunkmap_offset(map: &BTreeMap<u64, u64>, chunk_number: u64) -> Result<u64> {
    match map.range(chunk_number..).next() {
        Some((_, &v)) => Ok(v),
        None => Err(ZffError::new(
			ZffErrorKind::NotFound, 
			format!("{ERROR_COULD_NOT_FIND_EXPECTED_CHUNK_NUMBER_IN_MAP}{chunk_number}"))),
    }
}


fn get_first_chunknumber(map: &BTreeMap<u64, u64>, chunk_number: u64, first_segment_chunk_number: u64) -> Result<u64> {
    let mut range = map.range(..chunk_number).rev();
    match range.next() {
        Some((&k, _)) => Ok(k + 1),
        None => if chunk_number >= first_segment_chunk_number {
        	Ok(first_segment_chunk_number)
        } else {
        	Err(ZffError::new(
				ZffErrorKind::NotFound, 
				format!("{ERROR_COULD_NOT_FIND_EXPECTED_CHUNK_NUMBER_IN_MAP}{chunk_number}")))
        },
    }
}