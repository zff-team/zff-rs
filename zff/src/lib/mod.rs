#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

//! This crate provides the reference implementation of the forensic file format ZFF.\
//! ZFF is a new file format for forensic images, as an alternative to EWF and AFF.\
//! ZFF is focused on speed and security.
//! If you want to learn more about ZFF, visit <https://github.com/ph0llux/zff>.

// - modules
mod error;
mod constants;
mod traits;
mod compression;
mod encryption;
mod file_extension;
mod io;
mod hashing;
mod signatures;
mod segment;
/// all zff header.
pub mod header;
pub mod footer;

// - re-exports
pub use error::*;
pub use constants::*;
pub use traits::*;
pub use compression::*;
pub use encryption::*;
pub use file_extension::*;
pub use io::*;
pub use hashing::*;
pub use signatures::*;
pub use segment::*;

// - types
/// Result for std::result::Result<T, ZffError>.
pub type Result<T> = std::result::Result<T, ZffError>;