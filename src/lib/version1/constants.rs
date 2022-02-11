pub(crate) use crate::constants::*;

pub(crate) const DEFAULT_LENGTH_SEGMENT_FOOTER_EMPTY: usize = 21;
pub(crate) const DEFAULT_SEGMENT_FOOTER_VERSION: u8 = 1;
pub(crate) const ERROR_MISSING_SEGMENT: &'static str = "A segment is missing.";
pub(crate) const ERROR_REWRITE_MAIN_HEADER: &'static str = "An error occurred while trying to rewrite the main header to the output file. The written data length specified is not correctly listed in the header.";


// default header versions.
/// current header version for the [MainHeader](crate::header::MainHeader).
pub const DEFAULT_HEADER_VERSION_MAIN_HEADER: u8 = 1;
/// current header version for the [SegmentHeader](crate::header::SegmentHeader).
pub const DEFAULT_HEADER_VERSION_SEGMENT_HEADER: u8 = 1;