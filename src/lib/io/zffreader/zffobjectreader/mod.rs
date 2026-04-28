// - Parent
use super::*;

// - modules
mod zffobjectreader_encrypted;
mod zffobjectreader_logical;
mod zffobjectreader_physical;
mod zffobjectreader_virtual;
mod zffobjectreader_virtual_logical;

// re-exports
pub(crate) use zffobjectreader_encrypted::*;
pub(crate) use zffobjectreader_logical::*;
pub(crate) use zffobjectreader_physical::*;
pub(crate) use zffobjectreader_virtual::*;
pub(crate) use zffobjectreader_virtual_logical::*;

type ArcFileMetadaMap = Arc<HashMap<u64, FileMetadata>>;

#[derive(Debug)]
pub(crate) struct ObjectMetadata {
	pub header: ObjectHeader,
	pub footer: ObjectFooter,
	pub files: Option<ArcFileMetadaMap>,
}

impl ObjectMetadata {
	pub(crate) fn new(header: ObjectHeader, footer: ObjectFooter) -> Self {
		Self { header, footer, files: None }
	}
}

/// An enum, which provides an appropriate object reader.
#[derive(Debug)]
pub(crate) enum ZffObjectReader<R: Read + Seek> {
	/// Contains a [ZffObjectReaderPhysical].
	Physical(Box<ZffObjectReaderPhysical<R>>),
	/// Contains a [ZffObjectReaderLogical].
	Logical(Box<ZffObjectReaderLogical<R>>),
	/// Contains a [ZffObjectReaderVirtual].
	Virtual(Box<ZffObjectReaderVirtual<R>>),
	// Contains a [ZffObjectReaderVirtualLogical].
	VirtualLogical(Box<ZffObjectReaderVirtualLogical<R>>),
	/// Contains a [ZffObjectReaderEncrypted].
	Encrypted(Box<ZffObjectReaderEncrypted<R>>),
}

impl<R: Read + Seek> Read for ZffObjectReader<R> {
	fn read(&mut self, buf: &mut [u8]) -> std::result::Result<usize, std::io::Error> {
		match self {
			ZffObjectReader::Physical(reader) => reader.read(buf),
			ZffObjectReader::Logical(reader) => reader.read(buf),
			ZffObjectReader::Virtual(reader) => reader.read(buf),
			ZffObjectReader::VirtualLogical(reader) => reader.read(buf),
  			ZffObjectReader::Encrypted(_) => Err(
				std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
		}
	}
}

impl<R: Read + Seek> Seek for ZffObjectReader<R> {
	fn seek(&mut self, seek_from: std::io::SeekFrom) -> std::result::Result<u64, std::io::Error> {
		match self {
			ZffObjectReader::Physical(reader) => reader.seek(seek_from),
			ZffObjectReader::Logical(reader) => reader.seek(seek_from),
			ZffObjectReader::Virtual(reader) => reader.seek(seek_from),
			ZffObjectReader::VirtualLogical(reader) => reader.seek(seek_from),
			ZffObjectReader::Encrypted(_) => Err(std::io::Error::new(std::io::ErrorKind::NotFound, ERROR_ZFFREADER_OPERATION_ENCRYPTED_OBJECT)),
		}
	}
}