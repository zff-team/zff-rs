// - modules
/// This module contains the version 1 of all zff footer.
pub mod version1;
/// This module contains the version 2 of all zff footer.
pub mod version2;

// - re-exports -- this section contains the footer of the current zff version.
pub use version2::file_footer::*;
pub use version2::main_footer::*;
pub use version2::object_footer::*;
pub use version2::segment_footer::*;