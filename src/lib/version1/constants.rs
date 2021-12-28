pub(crate) use crate::constants::*;

pub(crate) const DEFAULT_LENGTH_SEGMENT_FOOTER_EMPTY: usize = 21;
pub(crate) const DEFAULT_SEGMENT_FOOTER_VERSION: u8 = 1;

// default header versions.
/// current header version for the [MainHeader](crate::header::MainHeader).
pub const DEFAULT_HEADER_VERSION_MAIN_HEADER: u8 = 1;
/// current header version for the [CompressionHeader](crate::header::CompressionHeader).
pub const DEFAULT_HEADER_VERSION_COMPRESSION_HEADER: u8 = 1;
/// current header version for the [DescriptionHeader](crate::header::DescriptionHeader).
pub const DEFAULT_HEADER_VERSION_DESCRIPTION_HEADER: u8 = 1;
/// current header version for the [SegmentHeader](crate::header::SegmentHeader).
pub const DEFAULT_HEADER_VERSION_SEGMENT_HEADER: u8 = 1;