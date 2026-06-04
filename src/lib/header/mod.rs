//! Module containing all header types for the zff format.
//!
//! Headers in zff containers provide metadata and structure information at the beginning
//! of various elements. Each header type has a unique magic identifier and version number.
//!
//! This module contains submodules for different header types:
//! segment_header, object_header, file_header, chunk_map, compression_header,
//! description_header, pbe_header, hash_header, encryption_header, chunk_header.
//!
//! All header types from the submodules are re-exported here for convenient access.

// - modules
mod segment_header;
mod object_header;
mod file_header;
mod chunk_map;
mod compression_header;
mod description_header;
mod pbe_header;
mod hash_header;
mod encryption_header;
mod chunk_header;

// - re-export
pub use hash_header::*;
pub use encryption_header::*;
pub use pbe_header::*;
pub use compression_header::*;
pub use description_header::*;
pub use segment_header::*;
pub use object_header::*;
pub use file_header::*;
pub use chunk_map::*;
pub use chunk_header::*;