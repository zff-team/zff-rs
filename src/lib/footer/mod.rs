// - modules
/// This module contains the version 1 of all zff footer.
pub mod version1;
/// This module contains the version 2 of all zff footer.
pub mod version2;

mod main_footer;

pub mod file_footer;
pub mod object_footer;

// - re-exports -- this section contains the footer of the current zff version.
pub use main_footer::*;
pub use version2::segment_footer::*;
pub use file_footer::*;
pub use object_footer::*;