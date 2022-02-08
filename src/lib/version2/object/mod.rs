// - STD
use std::collections::HashMap;

// - modules
mod encoder;

// - re-exports
pub use encoder::*;

// - internal
use crate::{
	Result,
	ZffError,
	ZffErrorKind,
	header::{ObjectHeader},
	footer::{ObjectFooterPhysical, ObjectFooterLogical},
	File,
};

pub enum Object {
	Physical(PhysicalObjectInformation),
	Logical(LogicalObjectInformation)
}

impl Object {
	pub fn position(&self) -> u64 {
		match self {
			Object::Physical(obj) => obj.position(),
			Object::Logical(obj) => obj.position()
		}
	}

	pub fn set_position(&mut self, position: u64) {
		match self {
			Object::Physical(obj) => obj.set_position(position),
			Object::Logical(obj) => obj.set_position(position)
		}
	}
}

pub struct PhysicalObjectInformation {
	header: ObjectHeader,
	footer: ObjectFooterPhysical,
	position: u64,
}

impl PhysicalObjectInformation {
	pub fn new(header: ObjectHeader, footer: ObjectFooterPhysical) -> Self {
		Self {
			header: header,
			footer: footer,
			position: 0,
		}
	}

	pub fn header(&self) -> &ObjectHeader {
		&self.header
	}

	pub fn footer(&self) -> &ObjectFooterPhysical {
		&self.footer
	}

	pub fn position(&self) -> u64 {
		self.position
	}

	pub fn set_position(&mut self, position: u64) {
		self.position = position
	}
}

pub struct LogicalObjectInformation {
	header: ObjectHeader,
	footer: ObjectFooterLogical,
	files: HashMap<u64, File>, // <File number, file>
	active_file_number: u64,
}

impl LogicalObjectInformation {
	pub fn new(header: ObjectHeader, footer: ObjectFooterLogical) -> Self {
		Self {
			header: header,
			footer: footer,
			files: HashMap::new(),
			active_file_number: 0,
		}
	}

	pub fn header(&self) -> &ObjectHeader {
		&self.header
	}

	pub fn footer(&self) -> &ObjectFooterLogical {
		&self.footer
	}

	pub fn active_file_number(&self) -> u64 {
		self.active_file_number
	}

	pub fn set_active_file_number(&mut self, file_number: u64) -> Result<()> {
		match self.files.get(&file_number) {
			Some(_) => self.active_file_number = file_number,
			None => return Err(ZffError::new(ZffErrorKind::MissingFileNumber, file_number.to_string())),
		}
		Ok(())
	}

	pub fn files(&self) -> &HashMap<u64, File> {
		&self.files
	}

	pub fn add_file(&mut self, file_number: u64, file: File) {
		self.files.insert(file_number, file);
	}

	pub fn get_active_file(&self) -> Result<File> {
		match self.files.get(&self.active_file_number) {
			Some(file) =>  Ok(file.clone()),
			None => return Err(ZffError::new(ZffErrorKind::MissingFileNumber, self.active_file_number.to_string())),
		}
	} 

	pub fn position(&self) -> u64 {
		match self.files.get(&self.active_file_number) {
			Some(file) => file.position(),
			None => 0,
		}
	}

	pub fn set_position(&mut self, position: u64) {
		match self.files.get_mut(&self.active_file_number) {
			Some(file) => file.set_position(position),
			None => (),
		}
	}
}