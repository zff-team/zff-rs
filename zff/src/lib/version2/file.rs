// - STD
use std::io::{Read};

// - internal
use crate::version2::{
	header::{FileHeader},
	footer::{FileFooter},
};
use crate::{
	Result,
	ZffError,
	ZffErrorKind,
};

#[derive(Debug,Clone)]
pub struct File<F: Read> {
	header: FileHeader,
	footer: FileFooter,
	entry_type: EntryType<F>
}

impl<F: Read> File<F> {
	pub fn header(&self) -> &FileHeader {
		&self.header
	}

	pub fn footer(&self) -> &FileFooter {
		&self.footer
	}

	pub fn entry_type(&self) -> &EntryType<F> {
		&self.entry_type
	}
}

#[derive(Debug,Clone)]
pub enum EntryType<F: Read> {
	File(F),
	Directory(Vec<u64>),
	Symlink(String),
}

impl<F: Read> EntryType<F> {
	//Method is only available for EntryType::Directory, otherwise it will return an error.
	pub fn get_offsets(&self) -> Result<&Vec<u64>> {
		match self {
			EntryType::Directory(offsets) => Ok(offsets),
			_ => Err(ZffError::new(ZffErrorKind::NotAvailableForEntryType, ""))
		}
	}
}