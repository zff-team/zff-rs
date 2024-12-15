#![forbid(unsafe_code)]
#![deny(missing_docs)]
//#![deny(warnings)]
//! This crate provides the reference implementation of the forensic file format Zff.
//! Zff is a new file format for forensic images, as an alternative to EWF and AFF.
//! Zff is focused on speed and security. If you want to learn more about ZFF, visit [https://github.com/ph0llux/zff](https://github.com/ph0llux/zff).

// adds #![feature(windows_by_handle)] to the crate for windows platforms only.
#![cfg_attr(target_os = "windows", feature(windows_by_handle))]


// - modules
/// This module contains all constants, used in this crate.
pub mod constants;
/// This module contains all header, could be found in the zff specification (header version 1 and header version 2).
pub mod header;
/// This module contains all footer, could be found in the zff specification (footer version 1 and footer version 2).
pub mod footer;
/// Contains several stuff to handle zff container (e.g. create, extend or read zff container).
pub mod io;
/// Contains some little helper functions
pub mod helper;
mod hashing;
mod compression;
/// Contains various functions, methods and traits to handle encryption in zff.
pub mod encryption;
mod traits;
mod error;
mod signatures;
mod file_extension;
mod object;
mod file;
mod segment;
mod chunk;

// - re-exports
pub use hashing::*;
pub use compression::*;
pub use encryption::*;
pub use error::*;
pub use signatures::*;
pub use traits::*;
pub use file_extension::*;
use constants::*;
pub use object::*;
pub use file::*;
pub use segment::*;
pub use chunk::*;

// - types
/// Result for std::result::Result<T, ZffError>.
pub type Result<T> = std::result::Result<T, ZffError>;