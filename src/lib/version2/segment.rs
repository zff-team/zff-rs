// - STD
use core::borrow::Borrow;
use std::io::{Read, Seek, SeekFrom};

// - internal
use crate::{
	Result,
	HeaderCoding,
	ValueDecoder,
	ZffError,
	ZffErrorKind,
	Chunk,
	Encryption,
	CompressionAlgorithm,
	decompress_buffer,
	header::{SegmentHeader, ObjectHeader, ChunkHeader, EncryptedChunkHeader, EncryptionInformation},
	footer::{SegmentFooter, ObjectFooter, EncryptedObjectFooter},
	ERROR_MISSING_OBJECT_HEADER_IN_SEGMENT,
	ERROR_MISSING_OBJECT_FOOTER_IN_SEGMENT,
	DEFAULT_LENGTH_HEADER_IDENTIFIER,
	DEFAULT_LENGTH_VALUE_HEADER_LENGTH,
};

/// Represents a full [Segment], containing a [crate::header::SegmentHeader],
/// a [crate::footer::SegmentFooter], a [Reader](std::io::Read) to the appropriate
/// segmented data and a position marker for this [Reader](std::io::Read). 
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
			header,
			data,
			footer,
			raw_reader_position: 0,
		}
	}

	/// Creates a new [Segment] from the given [Reader](std::io::Read).
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

	/// Returns a reference to the underlying [crate::header::SegmentHeader].
	pub fn header(&self) -> &SegmentHeader {
		&self.header
	}

	/// Returns a reference to the underlying [crate::footer::SegmentFooter].
	pub fn footer(&self) -> &SegmentFooter {
		&self.footer
	}

	/// Returns the raw chunk, if so present, then also encrypted and/or compressed.
	pub fn raw_chunk(&mut self, chunk_number: u64) -> Result<Chunk> {
		let chunk_offset = self.get_chunk_offset(&chunk_number)?;
		self.data.seek(SeekFrom::Start(chunk_offset))?;
		Chunk::new_from_reader(&mut self.data)
	}

	pub fn get_chunk_offset(&mut self, chunk_number: &u64) -> Result<u64> {
		let first_map_chunk_number = self.footer.chunk_map_table
								 .range(..chunk_number).next_back()
								 .map(|(k, _)| *k + 1)
								 .unwrap_or(self.footer.first_chunk_number);
		let chunk_map_offset = match self.footer.chunk_map_table.range((chunk_number + 1)..).next().map(|(_, offset)| *offset) {
			Some(offset) => offset,
			None => return Err(ZffError::new(ZffErrorKind::DataDecodeChunkNumberNotInSegment, chunk_number.to_string())),
		};
		
		// skips the chunk map header and the other chunk entries.
		let seek_offset = DEFAULT_LENGTH_HEADER_IDENTIFIER as u64 + 
						  DEFAULT_LENGTH_VALUE_HEADER_LENGTH as u64 +
						  1 + // skip the ChunkMap header version
						  ((chunk_number - first_map_chunk_number) * 2 * 8) +
						  chunk_map_offset +
						  8; // skip the chunk number itself and go directly to the appropiate offset;

		//go to the appropriate chunk map.
		self.data.seek(SeekFrom::Start(seek_offset))?;
		u64::decode_directly(&mut self.data)
	}

	/// Returns the chunked data, uncompressed and unencrypted
	pub fn chunk_data<E, C>(&mut self, chunk_number: u64, encryption_information: Option<E>, compression_algorithm: C) -> Result<Vec<u8>>
	where
		E: Borrow<EncryptionInformation>,
		C: Borrow<CompressionAlgorithm>,
	{
		let chunk_offset = self.get_chunk_offset(&chunk_number)?;
		self.data.seek(SeekFrom::Start(chunk_offset))?;

		let (compression_flag, chunk_size) = if encryption_information.is_some() {
			let chunk_header = EncryptedChunkHeader::decode_directly(&mut self.data)?;
			let compression_flag = chunk_header.flags.compression;
			let chunk_size = chunk_header.chunk_size;
			self.data.seek(SeekFrom::Start(chunk_header.header_size() as u64 + chunk_offset))?;
			(compression_flag, chunk_size)
		} else {
			let chunk_header = ChunkHeader::decode_directly(&mut self.data)?;
			let compression_flag = chunk_header.flags.compression;
			let chunk_size = chunk_header.chunk_size;
			self.data.seek(SeekFrom::Start(chunk_header.header_size() as u64 + chunk_offset))?;
			(compression_flag, chunk_size)
		};
		let mut raw_data_buffer = vec![0u8; chunk_size as usize];
		self.data.read_exact(&mut raw_data_buffer)?;
		
		if let Some(enc_info) = encryption_information {
			let enc_info = enc_info.borrow();
			raw_data_buffer = Encryption::decrypt_chunk_content(
				&enc_info.encryption_key, 
				raw_data_buffer, 
				chunk_number, 
				&enc_info.algorithm)?;
		}
		if compression_flag {
			decompress_buffer(&raw_data_buffer, compression_algorithm.borrow())
		} else {
			Ok(raw_data_buffer)
		}
	}

	/// Returns the [crate::header::ObjectHeader] of the given object number, if available in this [Segment]. Otherwise, returns an error.
	pub fn read_object_header(&mut self, object_number: u64) -> Result<ObjectHeader> {
		let offset = match self.footer.object_header_offsets().get(&object_number) {
				Some(value) => value,
				None => return Err(ZffError::new(ZffErrorKind::MalformedSegment, format!("{ERROR_MISSING_OBJECT_HEADER_IN_SEGMENT}{object_number}"))),
		};
		self.data.seek(SeekFrom::Start(*offset))?;
		let object_header = ObjectHeader::decode_directly(&mut self.data)?;
		Ok(object_header)
	}

	/// Returns the [crate::header::ObjectHeader] of the given object number (decrypts the encrypted object header on-the-fly with the given decryption password).
	/// # Error
	/// Fails if the [crate::header::ObjectHeader] could not be found in this [Segment] or/and if the decryption password is wrong.
	pub fn read_encrypted_object_header<P>(&mut self, object_number: u64, decryption_password: P) -> Result<ObjectHeader>
	where
		P: AsRef<[u8]>,
	{
		let offset = match self.footer.object_header_offsets().get(&object_number) {
				Some(value) => value,
				None => return Err(ZffError::new(ZffErrorKind::MalformedSegment, format!("{ERROR_MISSING_OBJECT_HEADER_IN_SEGMENT}{object_number}"))),
		};
		self.data.seek(SeekFrom::Start(*offset))?;
		let object_header = ObjectHeader::decode_encrypted_header_with_password(&mut self.data, decryption_password)?;
		Ok(object_header)
	}

	/// Returns the [crate::footer::ObjectFooter] of the given object number, if available in this [Segment]. Otherwise, returns an error.
	pub fn read_object_footer(&mut self, object_number: u64) -> Result<ObjectFooter> {
		let offset = match self.footer.object_footer_offsets().get(&object_number) {
			Some(value) => value,
			None => return Err(ZffError::new(ZffErrorKind::MalformedSegment, format!("{ERROR_MISSING_OBJECT_FOOTER_IN_SEGMENT}{object_number}"))),
		};
		self.data.seek(SeekFrom::Start(*offset))?;
		ObjectFooter::decode_directly(&mut self.data)
	}

	/// Returns the [crate::header::ObjectFooter] of the given object number (decrypts the encrypted object footer on-the-fly with the given decryption password).
	/// # Error
	/// Fails if the [crate::header::ObjectFooter] could not be found in this [Segment] or/and if the decryption password is wrong.
	pub fn read_encrypted_object_footer<E>(&mut self, object_number: u64, encryption_information: E) -> Result<ObjectFooter>
	where
		E: Borrow<EncryptionInformation>,
	{
		let offset = match self.footer.object_footer_offsets().get(&object_number) {
				Some(value) => value,
				None => return Err(ZffError::new(ZffErrorKind::MalformedSegment, format!("{ERROR_MISSING_OBJECT_FOOTER_IN_SEGMENT}{object_number}"))),
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