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
	header::{ObjectHeader, EncryptionHeader},
	footer::{ObjectFooter, ObjectFooterPhysical, ObjectFooterLogical},
	File,
	EncryptionAlgorithm,
};

/// The [Object] contains the appropriate object information.
#[derive(Debug, Clone)]
pub enum Object {
	/// Contains a [PhysicalObjectInformation] instance.
	Physical(Box<PhysicalObjectInformation>),
	/// Contains a [LogicalObjectInformation] instance.
	Logical(Box<LogicalObjectInformation>)
}

impl Object {

	/// Returns a new Object by given header, footer and optional encryption key.
	pub fn new(header: ObjectHeader, footer: ObjectFooter, encryption_key: Option<Vec<u8>>) -> Object {
		match footer {
			ObjectFooter::Physical(footer) => Self::Physical(Box::new(PhysicalObjectInformation::new(header, footer, encryption_key))),
			ObjectFooter::Logical(footer) => Self::Logical(Box::new(LogicalObjectInformation::new(header, footer, encryption_key))),
		}
	}

	/// Returns the used encryption algorithm of the underlying [ObjectHeader](crate::header::ObjectHeader), if available.
	pub fn encryption_algorithm(&self) -> Option<EncryptionAlgorithm> {
		match self {
			Object::Physical(obj) => Some(obj.header().encryption_header.as_ref()?.algorithm().clone()),
			Object::Logical(obj) => Some(obj.header().encryption_header.as_ref()?.algorithm().clone()),
		}
	}

	/// Returns the underlying encryption key, if available
	pub fn encryption_key(&self) -> Option<&Vec<u8>> {
		match self {
			Object::Physical(obj) => obj.encryption_key.as_ref(),
			Object::Logical(obj) => obj.encryption_key.as_ref(),
		}
	}

	/// Returns a reference of the underlying [ObjectHeader](crate::header::ObjectHeader).
	pub fn header(&self) -> &ObjectHeader {
		match self {
			Object::Physical(obj) => obj.header(),
			Object::Logical(obj) => obj.header(),
		}
	}

	/// Returns the object number of this object.
	pub fn object_number(&self) -> u64 {
		match self {
			Object::Physical(obj) => obj.header().object_number,
			Object::Logical(obj) => obj.header().object_number,
		}
	}

	/// Returns the underlying [EncryptionHeader](crate::header::EncryptionHeader), if available.
	pub fn encryption_header(&self) -> Option<&EncryptionHeader> {
		match self {
			Object::Physical(obj) => obj.header().encryption_header.as_ref(),
			Object::Logical(obj) => obj.header().encryption_header.as_ref(),
		}
	}

	/// Returns the current [Reader](std::io::Read) position.
	pub fn position(&self) -> u64 {
		match self {
			Object::Physical(obj) => obj.position(),
			Object::Logical(obj) => obj.position()
		}
	}

	/// Sets the position of the [Reader](std::io::Read).
	pub fn set_position(&mut self, position: u64) {
		match self {
			Object::Physical(obj) => obj.set_position(position),
			Object::Logical(obj) => obj.set_position(position)
		}
	}

	/// Returns the acquisition start time of the object.
	pub fn acquisition_start(&self) -> u64 {
		match self {
			Object::Physical(obj) => obj.footer.acquisition_start(),
			Object::Logical(obj) => obj.footer.acquisition_start(),
		}
	}

	/// Returns the acquisition end time of the object.
	pub fn acquisition_end(&self) -> u64 {
		match self {
			Object::Physical(obj) => obj.footer.acquisition_end(),
			Object::Logical(obj) => obj.footer.acquisition_end(),
		}
	}
}

/// This struct contains several information about a physical object.
#[derive(Debug, Clone)]
pub struct PhysicalObjectInformation {
	header: ObjectHeader,
	footer: ObjectFooterPhysical,
	encryption_key: Option<Vec<u8>>,
	position: u64,
}

impl PhysicalObjectInformation {
	/// Creates a new [PhysicalObjectInformation] with the given values.
	pub fn new(header: ObjectHeader, footer: ObjectFooterPhysical, encryption_key: Option<Vec<u8>>) -> Self {
		Self {
			header,
			footer,
			position: 0,
			encryption_key
		}
	}

	/// Returns a reference of the underlying object header.
	pub fn header(&self) -> &ObjectHeader {
		&self.header
	}

	/// Returns a reference of the underlying object footer.
	pub fn footer(&self) -> &ObjectFooterPhysical {
		&self.footer
	}

	/// Returns the current position of the appropriate [Reader](std::io::Read).
	pub fn position(&self) -> u64 {
		self.position
	}

	/// Sets the position for the appropriate [Reader](std::io::Read).
	pub fn set_position(&mut self, position: u64) {
		self.position = position
	}
}

/// This struct contains several information about a logical object.
#[derive(Debug, Clone)]
pub struct LogicalObjectInformation {
	header: ObjectHeader,
	footer: ObjectFooterLogical,
	encryption_key: Option<Vec<u8>>,
	files: HashMap<u64, File>, // <File number, file>
	active_file_number: u64,
}

impl LogicalObjectInformation {
	/// Creates a new [LogicalObjectInformation] with the given values.
	pub fn new(header: ObjectHeader, footer: ObjectFooterLogical, encryption_key: Option<Vec<u8>>) -> Self {
		Self {
			header,
			footer,
			files: HashMap::new(),
			active_file_number: 0,
			encryption_key,
		}
	}

	/// Returns a reference of the underlying object header.
	pub fn header(&self) -> &ObjectHeader {
		&self.header
	}

	/// Returns a reference of the underlying object footer.
	pub fn footer(&self) -> &ObjectFooterLogical {
		&self.footer
	}

	/// Returns the number of the current active file.
	pub fn active_file_number(&self) -> u64 {
		self.active_file_number
	}

	/// Sets the number of the current active file.
	/// # Error
	/// Fails, if the given file number not exists in this object.
	pub fn set_active_file_number(&mut self, file_number: u64) -> Result<()> {
		match self.files.get(&file_number) {
			Some(_) => self.active_file_number = file_number,
			None => return Err(ZffError::new(ZffErrorKind::MissingFileNumber, file_number.to_string())),
		}
		Ok(())
	}

	/// Returns a reference to a HashMap of the underlying [Files](crate::file::File) and their file numbers.
	pub fn files(&self) -> &HashMap<u64, File> {
		&self.files
	}

	/// Addss a file with its appropriate file number to the underlying HashMap of [Files](crate::file::File).
	pub fn add_file(&mut self, file_number: u64, file: File) {
		self.files.insert(file_number, file);
	}

	/// Returns a [File](crate::file::File) of the current active file.
	/// # Error
	/// Fails if the current set active file number is not available.
	pub fn get_active_file(&self) -> Result<File> {
		match self.files.get(&self.active_file_number) {
			Some(file) =>  Ok(file.clone()),
			None => Err(ZffError::new(ZffErrorKind::MissingFileNumber, self.active_file_number.to_string())),
		}
	} 

	/// Returns the current position of the appropriate [Reader](std::io::Read).
	pub fn position(&self) -> u64 {
		match self.files.get(&self.active_file_number) {
			Some(file) => file.position(),
			None => 0,
		}
	}

	/// Sets the position for the appropriate [Reader](std::io::Read).
	pub fn set_position(&mut self, position: u64) {
		if let Some(file) = self.files.get_mut(&self.active_file_number) { file.set_position(position) }
	}
}