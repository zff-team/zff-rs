// - STD
use std::sync::OnceLock;

// - Parent
use super::*;

// - modules
mod zffobjectreader_encrypted;
mod zffobjectreader_logical;
mod zffobjectreader_physical;
mod zffobjectreader_virtual;

// re-exports
pub(crate) use zffobjectreader_encrypted::*;
pub(crate) use zffobjectreader_logical::*;
pub(crate) use zffobjectreader_physical::*;
pub(crate) use zffobjectreader_virtual::*;

type ArcFileMetadata = Arc<HashMap<u64, FileMetadata>>;

#[derive(Debug)]
pub(crate) struct ObjectMetadata {
	pub header: ObjectHeader,
	pub footer: ObjectFooter,
	pub files: OnceLock<ArcFileMetadata>,
}

impl ObjectMetadata {
	pub(crate) fn new(header: ObjectHeader, footer: ObjectFooter) -> Self {
		Self { header, footer, files: OnceLock::new() }
	}
}

/// An enum, which provides an appropriate object reader.
#[derive(Debug)]
pub(crate) enum ZffObjectReader<R: ReadAt> {
	/// Contains a [ZffObjectReaderPhysical].
	Physical(Box<ZffObjectReaderPhysical<R>>),
	/// Contains a [ZffObjectReaderLogical].
	Logical(Box<ZffObjectReaderLogical<R>>),
	// Contains a [ZffObjectReaderVirtual].
	Virtual(Box<ZffObjectReaderVirtual<R>>),
	/// Contains a [ZffObjectReaderEncrypted].
	Encrypted(Box<ZffObjectReaderEncrypted<R>>),
}

impl<R: ReadAt> ZffObjectReader<R> {
	pub fn footer(&self) -> Result<ObjectFooter> {
		match self {
			ZffObjectReader::Physical(reader) => Ok(reader.object_footer()),
			ZffObjectReader::Logical(reader) => Ok(reader.object_footer()),
			ZffObjectReader::Virtual(reader) => Ok(reader.object_footer()),
			ZffObjectReader::Encrypted(_) => Err(ZffError::new(ZffErrorKind::Invalid, ""))
		}
	}

	pub fn read_at_file(&self, buf: &mut [u8], offset: u64, file_no: u64) -> std::io::Result<usize> {
		match self {
			// file no will be ignored in case of physical objects
			ZffObjectReader::Physical(reader) => reader.read_at(buf, offset),
			ZffObjectReader::Logical(reader) => reader.read_at_file(buf, offset, file_no),
			ZffObjectReader::Virtual(reader) => reader.read_at_file(buf, offset, file_no),
  			ZffObjectReader::Encrypted(_) => Err(
				std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
		}
	}

	pub fn read_at_file_to_end(&self, buf: &mut Vec<u8>, offset: u64, file_no: u64) -> std::io::Result<usize> {
		match self {
			// file no will be ignored in case of physical objects
			ZffObjectReader::Physical(reader) => reader.read_at_to_end(buf, offset),
			ZffObjectReader::Logical(reader) => reader.read_at_file_to_end(buf, offset, file_no),
			ZffObjectReader::Virtual(reader) => reader.read_at_file_to_end(buf, offset, file_no),
  			ZffObjectReader::Encrypted(_) => Err(
				std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
		}
	}
}

impl<R: ReadAt> ReadAt for ZffObjectReader<R> {
	fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
		match self {
			ZffObjectReader::Physical(reader) => reader.read_at(buf, offset),
			ZffObjectReader::Logical(reader) => reader.read_at(buf, offset),
			ZffObjectReader::Virtual(reader) => reader.read_at(buf, offset),
  			ZffObjectReader::Encrypted(_) => Err(
				std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
		}
	}

	fn size(&mut self) -> std::io::Result<u64> {
		match self {
			ZffObjectReader::Physical(reader) => reader.size(),
			ZffObjectReader::Logical(reader) => reader.size(),
			ZffObjectReader::Virtual(reader) => reader.size(),
  			ZffObjectReader::Encrypted(_) => Err(
				std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
		}
	}
}

impl<R: ReadAt> Read for ZffObjectReader<R> {
	fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
		match self {
			ZffObjectReader::Physical(reader) => reader.read(buf),
			ZffObjectReader::Logical(reader) => reader.read(buf),
			ZffObjectReader::Virtual(reader) => reader.read(buf),
  			ZffObjectReader::Encrypted(_) => Err(
				std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
		}
	}
}

impl<R: ReadAt> Seek for ZffObjectReader<R> {
	fn seek(&mut self, seek_from: std::io::SeekFrom) -> std::result::Result<u64, std::io::Error> {
		match self {
			ZffObjectReader::Physical(reader) => reader.seek(seek_from),
			ZffObjectReader::Logical(reader) => reader.seek(seek_from),
			ZffObjectReader::Virtual(reader) => reader.seek(seek_from),
			ZffObjectReader::Encrypted(_) => Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
		}
	}
}