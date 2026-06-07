//! Module containing all footer types for the zff format.
//!
//! Footers in zff containers provide metadata and integrity information at the end
//! of various structural elements. This module organizes all footer-related types
//! and functionality.
//!
//! This module contains submodules for different footer types:
//! main_footer, segment_footer, file_footer, object_footer, virtual_file_footer.
//!
//! All footer types from the submodules are re-exported here for convenient access.

// - modules
mod file_footer;
mod main_footer;
mod object_footer;
mod segment_footer;
mod virtual_file_footer;

// - re-exports -- this section contains the footer of the current zff version.
pub use file_footer::*;
pub use main_footer::*;
pub use object_footer::*;
pub use segment_footer::*;
pub use virtual_file_footer::*;
