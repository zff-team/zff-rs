#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![deny(warnings)]
//! This crate provides the reference implementation of the forensic file format Zff.
//! Zff is a new file format for forensic images, as an alternative to EWF and AFF.
//! Zff is focused on speed and security. If you want to learn more about ZFF, visit [https://codeberg.org/zff-team/zff-rs](https://codeberg.org/zff-team/zff-rs).

// adds #![feature(windows_by_handle)] to the crate for windows platforms only.
#![cfg_attr(target_os = "windows", feature(windows_by_handle))]

// - modules
mod chunk;
mod compression;
/// This module contains all constants, used in this crate.
pub mod constants;
/// Contains various functions, methods and traits to handle encryption in zff.
pub mod encryption;
mod error;
mod file;
mod file_extension;
/// This module contains all footer, could be found in the zff specification (footer version 1 and footer version 2).
pub mod footer;
mod hashing;
/// This module contains all header, could be found in the zff specification (header version 1 and header version 2).
pub mod header;
/// Contains some little helper functions
pub mod helper;
/// Contains various functionality to handle zff containers (e.g., create, extend, or read zff containers).
pub mod io;
mod object;
mod platform_string;
/// Re-exports commonly used types, traits, and constants for convenient access.
pub mod prelude;
mod segment;
mod signatures;
mod traits;

#[cfg(test)]
mod tests;

// - re-exports
pub use chunk::*;
pub use compression::*;
use constants::*;
pub use encryption::*;
pub use error::*;
pub use file::*;
pub use file_extension::*;
pub use hashing::*;
pub use object::*;
pub use platform_string::*;
pub use segment::*;
pub use signatures::*;
pub use traits::*;

// - external
use aes_gcm::Nonce as AesGcmNonce;
use typenum::consts::U12;

pub use phollpers::{
    traits::read_at::*,
    read_at::ReadAtCursor
};

// - types
/// Result for std::result::Result<T, ZffError>.
pub type Result<T> = std::result::Result<T, ZffError>;
type Nonce = AesGcmNonce<U12>; //use the (by NIST) recommended nonce size of 96-bit.
