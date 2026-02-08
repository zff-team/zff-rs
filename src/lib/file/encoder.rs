// - STD
use std::io::{Read, Cursor, Seek};
use std::path::PathBuf;
use std::rc::Rc;
use std::cell::RefCell;
use std::time::SystemTime;

// - internal
use crate::{
	header::{FileHeader, HashHeader, HashValue, EncryptionInformation, ObjectHeader, DeduplicationMetadata},
	footer::FileFooter,
};
use crate::{
	Result,
	EncodingState,
	io::{buffer_chunk, BufferedChunk},
	PreparedChunk,
	header::{ChunkFlags, ChunkHeader},
	HeaderCoding,
	ValueEncoder,
	EncodingThreadPoolManager,
	Signature,
	chunking,
};

#[cfg(feature = "log")]
use crate::hashes_to_log;

// - external
use time::OffsetDateTime;
use ed25519_dalek::SigningKey;

/// This enum contains the information, which are needed to encode the different file types.
pub enum FileTypeEncodingInformation {
	/// A regular file, which contains a Reader to the inner file content.
	File(Box<dyn Read>),
	/// A directory with the given children.
	Directory(Vec<u64>), // directory children,
	/// A symlink with the given real path.
	Symlink(PathBuf), // symlink real path
	/// A hardlink with the given twin filenumber.
	Hardlink(u64), // hardlink filenumber
	/// A special file with the given special file information.
	#[cfg(target_family = "unix")]
	SpecialFile(SpecialFileEncodingInformation), // special file information (rdev, type_flag)
}

/// This enum contains the information, which are needed to encode the different file types.
#[derive(Debug)]
pub enum _FileTypeEncodingInformation {
	/// A regular file.
	File,
	/// A directory with the given children.
	Directory(Vec<u64>), // directory children,
	/// A symlink with the given real path.
	Symlink(PathBuf), // symlink real path
	/// A hardlink with the given twin filenumber.
	Hardlink(u64), // hardlink filenumber
	/// A special file with the given special file information.
	#[cfg(target_family = "unix")]
	SpecialFile(SpecialFileEncodingInformation), // special file information (rdev, type_flag)
}

/// This enum contains the information, which are needed to encode the different special file types.
#[cfg(target_family = "unix")]
#[derive(Debug)]
pub enum SpecialFileEncodingInformation {
	/// A fifo file with the given rdev-id.
	Fifo(u64), // fifo(rdev),
	/// A char file with the given rdev-id.
	Char(u64), // char(rdev),
	/// A block file with the given rdev-id.
	Block(u64), // block(rdev),
	/// A socket file with the given rdev-id.
	Socket(u64), // socket(rdev),
}

/// The [FileEncoder] can be used to encode a [crate::file::File].
pub struct FileEncoder {
	/// The appropriate [FileHeader].
	file_header: FileHeader,
	/// The appropriate [ObjectHeader].
	object_header: ObjectHeader,
	filetype_encoding_information: FileTypeEncodingInformation,
	/// The optional signing key, to sign the hashes.
	signing_key: Option<SigningKey>,
	/// optional encryption information, to encrypt the data with the given key and algorithm
	encryption_information: Option<EncryptionInformation>,
	/// A reference counter to the encoding thread pool manager of the parent logical object encoder.
	encoding_thread_pool_manager: Rc<RefCell<EncodingThreadPoolManager>>,
	/// The first chunk number for this file.
	initial_chunk_number: u64,
	/// The current chunk number
	current_chunk_number: u64,
	/// The number of bytes, which were read from the underlying file.
	read_bytes_underlying_data: u64,
	acquisition_start: u64,
	acquisition_end: u64,
}

impl FileEncoder {
	/// creates a new [FileEncoder] with the given values.
	pub fn new(
		file_header: FileHeader,
		object_header: ObjectHeader,
		filetype_encoding_information: FileTypeEncodingInformation,
		encoding_thread_pool_manager: Rc<RefCell<EncodingThreadPoolManager>>,
		signing_key: Option<SigningKey>,
		encryption_information: Option<EncryptionInformation>,
		current_chunk_number: u64) -> Result<FileEncoder> {
		
		Ok(Self {
			file_header,
			object_header,
			encoding_thread_pool_manager,
			signing_key,
			encryption_information,
			initial_chunk_number: current_chunk_number,
			current_chunk_number,
			read_bytes_underlying_data: 0,
			acquisition_start: 0,
			acquisition_end: 0,
			filetype_encoding_information,
		})
	}

	/// Returns a reference of the appropriate file header
	pub fn file_header_ref(&self) -> &FileHeader {
		&self.file_header
	}

	/// returns the underlying encoded header
	pub fn get_encoded_header(&mut self) -> Vec<u8> {
		if self.acquisition_start == 0 {
			self.acquisition_start = OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64;
		}
		if let Some(enc_info) = &self.encryption_information {
			//unwrap should be safe here, because we have already testet this before.
	    	self.file_header.encode_encrypted_header_directly(enc_info).unwrap()
	    } else {
	    	self.file_header.encode_directly()
	    }
	}

	/// returns the encoded chunk - this method will increment the self.current_chunk_number automatically.
	pub(crate) fn get_next_chunk<D: Read + Seek>(
		&mut self, 
		deduplication_metadata: Option<&mut DeduplicationMetadata<D>>,
		) -> Result<EncodingState> {
		let chunk_size = self.object_header.chunk_size as usize;
		let mut eof = false;

		let buffered_chunk = match &mut self.filetype_encoding_information {
			FileTypeEncodingInformation::Directory(directory_children) => {
				let encoded_directory_children = if directory_children.is_empty() {
					Vec::<u64>::new().encode_directly()
				} else {
					directory_children.encode_directly()
				};
				let mut cursor = Cursor::new(&encoded_directory_children);
				cursor.set_position(self.read_bytes_underlying_data);
				let buffered_chunk = buffer_chunk(&mut cursor, chunk_size)?;
				self.read_bytes_underlying_data += buffered_chunk.bytes_read;
				buffered_chunk
			},
			FileTypeEncodingInformation::Symlink(symlink_real_path) => {
				let encoded_symlink_real_path = symlink_real_path.to_string_lossy().encode_directly();
				let mut cursor = Cursor::new(&encoded_symlink_real_path);
				cursor.set_position(self.read_bytes_underlying_data);
				let buffered_chunk = buffer_chunk(&mut cursor, chunk_size)?;
				self.read_bytes_underlying_data += buffered_chunk.bytes_read;
				if buffered_chunk.bytes_read > 0 {
					buffered_chunk
				} else {
					eof = true;
					BufferedChunk::default()
				}
			},
			FileTypeEncodingInformation::Hardlink(hardlink_filenumber) => {
				let encoded_hardlink_filenumber = hardlink_filenumber.encode_directly();
				let mut cursor = Cursor::new(&encoded_hardlink_filenumber);
				cursor.set_position(self.read_bytes_underlying_data);
				let buffered_chunk = buffer_chunk(&mut cursor, chunk_size)?;
				self.read_bytes_underlying_data += buffered_chunk.bytes_read;
				if buffered_chunk.bytes_read > 0 {
					buffered_chunk
				} else {
					eof = true;
					BufferedChunk::default()
				}	
			},
			FileTypeEncodingInformation::File(ref mut reader) => {
				let buffered_chunk = buffer_chunk(reader, chunk_size)?;
				self.read_bytes_underlying_data += buffered_chunk.bytes_read;
				buffered_chunk
			},
			// contains the rdev-id and a flag for the type of the special file 
			// (0 if fifo-, 1 if char-, 2 if block-, and 3 if it is a socket-file).
			#[cfg(target_family = "unix")]
			FileTypeEncodingInformation::SpecialFile(specialfile_encoding_information) => {
				let (rdev_id, type_flag) = match specialfile_encoding_information {
					SpecialFileEncodingInformation::Fifo(rdev_id) => (rdev_id, 0_u8),
					SpecialFileEncodingInformation::Char(rdev_id) => (rdev_id, 1),
					SpecialFileEncodingInformation::Block(rdev_id) => (rdev_id, 2),
					SpecialFileEncodingInformation::Socket(rdev_id) => (rdev_id, 3),
				};
				let mut encoded_data = rdev_id.encode_directly();
				encoded_data.append(&mut type_flag.encode_directly());
				let mut cursor = Cursor::new(&encoded_data);
				cursor.set_position(self.read_bytes_underlying_data);
				let buffered_chunk = buffer_chunk(&mut cursor, chunk_size)?;
				self.read_bytes_underlying_data += buffered_chunk.bytes_read;
				if buffered_chunk.bytes_read > 0 {
					buffered_chunk
				} else {
					eof = true;
					BufferedChunk::default()
				}
			}
		};

		if buffered_chunk.buffer.is_empty() && self.read_bytes_underlying_data != 0 || eof {
			//this case is the normal "file reader reached EOF".
			return Ok(EncodingState::ReadEOF);
		} else if buffered_chunk.buffer.is_empty() && self.read_bytes_underlying_data == 0 {
			//this case is the "file is empty".
			let mut flags = ChunkFlags::default();
			flags.empty_file = true;
			let mut chunk_header = ChunkHeader::default();
			chunk_header.flags = flags;
			let prepared_chunk = PreparedChunk::new(Vec::new(), chunk_header, None, None);
			return Ok(EncodingState::PreparedChunk(prepared_chunk))
		};

		// Needed for the same byte check
		let buf_len = buffered_chunk.buffer.len() as u64;

		let mut encoding_thread_pool_manager = self.encoding_thread_pool_manager.borrow_mut();

		encoding_thread_pool_manager.update(buffered_chunk.buffer);

		let encryption_algorithm = self.encryption_information.as_ref().map(|encryption_information| &encryption_information.algorithm);
		let encryption_key = self.encryption_information.as_ref().map(|encryption_information| &encryption_information.encryption_key);

	    let chunk = chunking(
			&mut encoding_thread_pool_manager,
			self.current_chunk_number,
			buf_len,
			chunk_size as u64,
			deduplication_metadata,
			encryption_key,
			encryption_algorithm,
		)?;

		self.current_chunk_number += 1;
	    Ok(EncodingState::PreparedChunk(chunk))
	}

	/// returns the appropriate encoded [FileFooter].
	/// A call of this method finalizes the underlying hashers. You should be care.
	pub fn get_encoded_footer(&mut self) -> Result<Vec<u8>> {
		let mut encoding_thread_pool_manager = self.encoding_thread_pool_manager.borrow_mut();

		self.acquisition_end = OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64;
		let mut hash_values = Vec::new();
		for (hash_type, hash) in encoding_thread_pool_manager.finalize_all_hashing_threads() {
	        let mut hash_value = HashValue::new_empty(hash_type.clone());
	        hash_value.set_hash(hash.to_vec());
			if let Some(signing_key) = &self.signing_key {
				let signature = Signature::sign(signing_key, &hash);
				hash_value.set_ed25519_signature(signature);
			}
	        hash_values.push(hash_value);
	    }

		#[cfg(feature = "log")]
		hashes_to_log(self.object_header.object_number, Some(self.file_header.file_number), &hash_values);

		let hash_header = HashHeader::new(hash_values);
		let footer = FileFooter::new(
			self.file_header.file_number,
			self.acquisition_start,
			self.acquisition_end,
			hash_header,
			self.initial_chunk_number,
			self.current_chunk_number - self.initial_chunk_number,
			self.read_bytes_underlying_data,
			);
		if let Some(enc_info) = &self.encryption_information {
	    	footer.encode_encrypted_header_directly(enc_info)
	    } else {
	    	Ok(footer.encode_directly())
	    }
	}
}