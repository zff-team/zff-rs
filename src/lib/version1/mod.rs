#![forbid(unsafe_code)]
#![deny(missing_docs)]

// - modules
mod constants;
mod io;
mod segment;

// - re-exports
pub use constants::*;
pub use io::*;
pub use segment::*;
pub(crate) use super::{
	Result,
	ZffError,
	ZffErrorKind,
};