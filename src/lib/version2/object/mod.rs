// - modules
mod encoder;

// - re-exports
pub use encoder::*;

// - internal
use crate::{
	header::{ObjectHeader},
	footer::{ObjectFooterPhysical},
};

pub struct PhysicalObjectInformation {
	header: ObjectHeader,
	footer: ObjectFooterPhysical
}

impl PhysicalObjectInformation {
	pub fn new(header: ObjectHeader, footer: ObjectFooterPhysical) -> Self {
		Self {
			header: header,
			footer: footer
		}
	}

	pub fn header(&self) -> &ObjectHeader {
		&self.header
	}

	pub fn footer(&self) -> &ObjectFooterPhysical {
		&self.footer
	}
}