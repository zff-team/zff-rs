//! This module contains all footer structures of the zff standard version 1.
//! The zff standard version 1 defines only one footer structure, the [SegmentFooter](crate::footer::version1::SegmentFooter).

// - modules
pub(crate) mod segment_footer;

// re-exports
pub use segment_footer::*;