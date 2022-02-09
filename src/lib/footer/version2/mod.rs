// - modules
pub(crate) mod file_footer;
pub(crate) mod object_footer;
pub(crate) mod segment_footer;
pub(crate) mod main_footer;

// - re-exports
pub use file_footer::*;
pub use object_footer::*;
pub use segment_footer::*;
pub use main_footer::*;