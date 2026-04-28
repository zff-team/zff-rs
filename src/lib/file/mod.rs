// - Parent
use super::{*, header::*, footer::*, io::{buffer_chunk, BufferedChunk}};

// - modules
mod encoder;

// - re-exports
pub use encoder::*;

pub struct FileMapPosition {
	pub segment_no: u64,
	pub offset: u64
}

/// The [FileMetadata] contains the appropriate metadata for a zff logical file or a zff virtual logical file.
/// Also this struct contains a position value for a [Reader](std::io::Read).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FileMetadata {
	pub header: FileHeader,
	pub footer: FileFooterW,
}

impl FileMetadata {
	/// creates a new [File] instance for the given [FileHeader] and [FileFooter].
	pub fn with_file_footer(header: FileHeader, footer: FileFooter) -> Self {
		Self {
			header,
			footer: FileFooterW::FileFooter(footer),
		}
	}

	/// creates a new [File] instance for the given [FileHeader] and [VirtualFileFooter].
	pub fn with_virtual_file_footer(header: FileHeader, footer: VirtualFileFooter) -> Self {
		Self {
			header,
			footer: FileFooterW::VirtualFileFooter(footer),
		}
	}

	pub(crate) fn first_chunk_number(&self) -> Option<u64> {
		match &self.footer {
			FileFooterW::VirtualFileFooter(_) => None,
			FileFooterW::FileFooter(footer) => Some(footer.first_chunk_number),
		}
	}

	pub(crate) fn number_of_chunks(&self) -> Option<u64> {
		match &self.footer {
			FileFooterW::VirtualFileFooter(_) => None,
			FileFooterW::FileFooter(footer) => Some(footer.number_of_chunks),
		}
	}

	/// Returns the segmentnumber and offset of the appropriate filemap, in case of [VirtualFileFooter].
	/// Returns None in case of [FileFooter].
	pub(crate) fn filemap_position(&self) -> Result<FileMapPosition> {
		match &self.footer {
			FileFooterW::FileFooter(_) => return Err(ZffError::new(ZffErrorKind::Invalid, ERROR_ZFFREADER_MISSING_VLFM)),
			FileFooterW::VirtualFileFooter(footer) => Ok(FileMapPosition {
				segment_no: footer.file_map_segment_no,
				offset: footer.file_map_offset
			})
		}
	}

	/// returns the parent file number
	pub fn parent(&self) -> u64 {
		self.header.parent_file_number
	}

	/// returns the [FileType].
	pub fn filetype(&self) -> FileType {
		self.header.file_type.clone()
	}

	/// returns the length of the data, read from the underlying filefooter.
	pub fn length_of_data(&self) -> u64 {
		match &self.footer {
			FileFooterW::FileFooter(footer) => footer.length_of_data,
			FileFooterW::VirtualFileFooter(footer) => footer.length_of_data,
		}
	}
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum FileFooterW {
	FileFooter(FileFooter),
	VirtualFileFooter(VirtualFileFooter),
}
