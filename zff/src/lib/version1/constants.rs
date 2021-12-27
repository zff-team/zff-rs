pub(crate) use crate::constants::*;

//ZFF File extension
/// the start value for file extensions. a file-extension always starts with a 'z', followed by the segment number (e.g. "z01", "z02", ..., "z99", "z100", ...).
pub const FILE_EXTENSION_START: char = 'z';
/// the file extension for the first segment (which contains the main header also).
pub const FILE_EXTENSION_FIRST_VALUE: &str = "z01";

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
