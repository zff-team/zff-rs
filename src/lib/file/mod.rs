// - Parent
use super::{*, header::*, footer::*, io::{buffer_chunk, BufferedChunk}};

// - modules
mod encoder;

// - re-exports
pub use encoder::*;

/// The [FileMetadata] contains the appropriate metadata for a zff logical file or a zff virtual logical file.
/// Also this struct contains a position value for a [Reader](std::io::Read).
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct FileMetadata {
	header: FileHeader,
	footer: FileFooterW,
	pub position: u64,
}

impl FileMetadata {
	/// creates a new [File] instance for the given [FileHeader] and [FileFooter].
	pub fn with_file_footer(header: FileHeader, footer: FileFooter) -> Self {
		Self {
			header,
			footer: FileFooterW::FileFooter(footer),
			position: 0
		}
	}

	/// creates a new [File] instance for the given [FileHeader] and [VirtualFileFooter].
	pub fn with_virtual_file_footer(header: FileHeader, footer: VirtualFileFooter) -> Self {
		Self {
			header,
			footer: FileFooterW::VirtualFileFooter(footer),
			position: 0
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

	/// Returns a copy of the inner [FileHeader].
	pub fn fileheader(&self) -> FileHeader {
		self.header.clone()
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

	/// Returns the segment number and offset of the virtual logical file map.
	pub(crate) fn virtual_file_map_info(&self) -> Option<(u64, u64)> {
		match &self.footer {
			FileFooterW::FileFooter(_) => None,
			FileFooterW::VirtualFileFooter(footer) => Some((footer.file_map_segment_no, footer.file_map_offset)),
		}
	}
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum FileFooterW {
	FileFooter(FileFooter),
	VirtualFileFooter(VirtualFileFooter),
}
