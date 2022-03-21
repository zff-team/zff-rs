// - modules
mod encoder;

// - re-exports
pub use encoder::*;

// - internal
use crate::{
	header::{FileHeader, FileType},
	footer::{FileFooter},
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct File {
	header: FileHeader,
	footer: FileFooter,
	position: u64,
}

impl File {
	pub fn new(header: FileHeader, footer: FileFooter) -> File {
		Self {
			header: header,
			footer: footer,
			position: 0
		}
	}

	pub fn header(&self) -> &FileHeader {
		&self.header
	}

	pub fn footer(&self) -> &FileFooter {
		&self.footer
	}

	/// returns the parent file number
	pub fn parent(&self) -> u64 {
		self.header.parent_file_number()
	}

	pub fn filetype(&self) -> FileType {
		self.header.file_type()
	}

	pub fn position(&self) -> u64 {
		self.position
	}

	pub fn set_position(&mut self, position: u64) {
		self.position = position
	}

	pub fn length_of_data(&self) -> u64 {
		self.footer.length_of_data()
	}
}