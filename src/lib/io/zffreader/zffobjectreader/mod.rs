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

#[derive(Debug)]
pub(crate) struct ObjectMetadata {
	pub header: ObjectHeader,
	pub footer: ObjectFooter,
}

impl ObjectMetadata {
	pub(crate) fn new(header: ObjectHeader, footer: ObjectFooter) -> Self {
		Self { header, footer }
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


/// The Metadata of a [File](crate::file::File).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FileMetadata {
	/// The file number of the parent directory (0 if the parent directory is the root directory).
	pub parent_file_number: u64,
	/// The length of the file in bytes.
	pub length_of_data: u64,
	/// The first chunk number used by this file.
	pub first_chunk_number: u64,
	/// The number of all chunks which are used for this file.
	pub number_of_chunks: u64,
	/// Position of the internal reader. This is mostly internally used.
	pub position: u64,
	/// The appropriate type of the file.
	pub file_type: FileType,
	/// The appropriate filename.
	pub filename: Option<PlatformString>,
	/// The metadata of the appropriate file.
	pub metadata_ext: HashMap<String, MetadataExtendedValue>,
	/// The timestamp when the acquisition has started.
	pub acquisition_start: Option<u64>,
	/// The timestamp when the acquisition has ended.
	pub acquisition_end: Option<u64>,
	/// The appropriate hash header of the file. 
	pub hash_header: Option<HashHeader>,
}

impl FileMetadata {
	/// Creates the [FileMetadata] with minimum amount of data. Most optional fields will be "None" and have to
	/// read directly from zff container.
	/// This Method will reduce the memory usage in the most possible way.
	/// This Option will provide:  
	/// - the parent file number
	/// - the length (or size) of the file
	/// - the first chunk number
	/// - the number of chunks
	/// - the internally used reader position
	/// - the filetype
	pub fn with_header_minimal(fileheader: &FileHeader, filefooter: &FileFooter) -> Self {
		Self {
			parent_file_number: fileheader.parent_file_number,
			length_of_data: filefooter.length_of_data,
			first_chunk_number: filefooter.first_chunk_number,
			number_of_chunks: filefooter.number_of_chunks,
			position: 0,
			file_type: fileheader.file_type.clone(),
			filename: None,
			metadata_ext: HashMap::new(),
			acquisition_start: None,
			acquisition_end: None,
			hash_header: None,
		}
	}

	/// Creates the [FileMetadata] with recommended amount of data. Most optional fields will be "None" and have to
	/// read directly from zff container.
	/// This Method will reduce the memory usage a bit.
	/// This Option will provide:  
	/// - the parent file number
	/// - the length (or size) of the file
	/// - the first chunk number
	/// - the number of chunks
	/// - the internally used reader position
	/// - the filetype
	/// - the filename
	/// - the metadata of the file
	pub fn with_header_recommended(fileheader: &FileHeader, filefooter: &FileFooter) -> Self {
		Self {
			parent_file_number: fileheader.parent_file_number,
			length_of_data: filefooter.length_of_data,
			first_chunk_number: filefooter.first_chunk_number,
			number_of_chunks: filefooter.number_of_chunks,
			position: 0,
			file_type: fileheader.file_type.clone(),
			filename: Some(fileheader.filename.clone()),
			metadata_ext: extract_recommended_metadata(fileheader),
			acquisition_start: None,
			acquisition_end: None,
			hash_header: None,
		}
	}

	/// Creates the [FileMetadata] with recommended amount of data. Most optional fields will be "None" and have to
	/// read directly from zff container.
	/// This Method will reduce the need of I/O access in the most possible way.
	/// This Option will provide:  
	/// - the parent file number
	/// - the length (or size) of the file
	/// - the first chunk number
	/// - the number of chunks
	/// - the internally used reader position
	/// - the filetype
	/// - the filename
	/// - the metadata of the file
	/// - the timestamps of start and end of the acquisition
	/// - the appropriate hash header
	pub fn with_header_all(fileheader: &FileHeader, filefooter: &FileFooter) -> Self {
		Self {
			parent_file_number: fileheader.parent_file_number,
			length_of_data: filefooter.length_of_data,
			first_chunk_number: filefooter.first_chunk_number,
			number_of_chunks: filefooter.number_of_chunks,
			position: 0,
			file_type: fileheader.file_type.clone(),
			filename: Some(fileheader.filename.clone()),
			metadata_ext: extract_all_metadata(fileheader),
			acquisition_start: Some(filefooter.acquisition_start),
			acquisition_end: Some(filefooter.acquisition_end),
			hash_header: Some(filefooter.hash_header.clone()),
		}
	}
}

#[derive(Debug)]
enum PreloadDegree {
	//Minimal,
	Recommended,
	//All,
}