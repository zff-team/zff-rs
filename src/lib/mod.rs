#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! This crate provides the reference implementation of the forensic file format Zff.
//! Zff is a new file format for forensic images, as an alternative to EWF and AFF.
//! Zff is focused on speed and security. If you want to learn more about ZFF, visit [https://github.com/ph0llux/zff](https://github.com/ph0llux/zff).

// - modules
/// This module contains several structs and methods to create, read and extend zff container in version 2.
pub mod version2;
/// This module contains all constants, used in this crate.
pub mod constants;
/// This module contains all header, could be found in the zff specification (header version 1 and header version 2).
pub mod header;
/// This module contains all footer, could be found in the zff specification (footer version 1 and footer version 2).
pub mod footer;
mod hashing;
mod compression;
mod encryption;
mod traits;
mod error;
mod signatures;
mod file_extension;
pub mod io;

// - re-exports
pub use hashing::*;
pub use compression::*;
pub use encryption::*;
pub use error::*;
pub use signatures::*;
pub use traits::*;
pub use file_extension::*;
use constants::*;
//
pub use version2::*;
//pub use version2::io::*; //TODO

// - types
/// Result for std::result::Result<T, ZffError>.
pub type Result<T> = std::result::Result<T, ZffError>;