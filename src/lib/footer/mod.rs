// - modules
mod main_footer;
mod segment_footer;
pub mod file_footer;
pub mod object_footer;

// - re-exports -- this section contains the footer of the current zff version.
pub use main_footer::*;
pub use segment_footer::*;
pub use file_footer::*;
pub use object_footer::*;