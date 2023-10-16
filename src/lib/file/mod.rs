// - modules
mod encoder;

// - re-exports
pub use encoder::*;

// - internal
use crate::{
	header::{FileHeader, FileType},
	footer::{FileFooter},
};

/// The [File] contains the appropriate [FileHeader] and [FileFooter] of a dumped [File].
/// Also this struct contains a position value for a [Reader](std::io::Read).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct File {
	header: FileHeader,
	footer: FileFooter,
	position: u64,
}

impl File {
	/// creates a new [File] instance for the given [FileHeader] and [FileFooter].
	pub fn new(header: FileHeader, footer: FileFooter) -> File {
		Self {
			header,
			footer,
			position: 0
		}
	}

	/// returns a reference of the underlying [FileHeader].
	pub fn header(&self) -> &FileHeader {
		&self.header
	}

	/// returns a reference of the underlying [FileFooter].
	pub fn footer(&self) -> &FileFooter {
		&self.footer
	}

	/// returns the parent file number
	pub fn parent(&self) -> u64 {
		self.header.parent_file_number
	}

	/// returns the [FileType].
	pub fn filetype(&self) -> FileType {
		self.header.file_type.clone()
	}

	/// returns the position of the [Reader](std::io::Read) used for this [File].
	pub fn position(&self) -> u64 {
		self.position
	}

	/// sets the position of the [Reader](std::io::Read).
	pub fn set_position(&mut self, position: u64) {
		self.position = position
	}

	/// returns the length of the data, read from the underlying [FileFooter].
	pub fn length_of_data(&self) -> u64 {
		self.footer.length_of_data()
	}
}