// identifier: magic bytes
pub(crate) const HEADER_IDENTIFIER_MAIN_HEADER: u32 = 0x7A66666d;
pub(crate) const HEADER_IDENTIFIER_ENCRYPTED_MAIN_HEADER: u32 = 0x7a666645;
pub(crate) const HEADER_IDENTIFIER_DESCRIPTION_HEADER: u32 = 0x7A666664;
pub(crate) const HEADER_IDENTIFIER_SEGMENT_HEADER: u32 = 0x7A666673;
pub(crate) const HEADER_IDENTIFIER_COMPRESSION_HEADER: u32 = 0x7A666663;
pub(crate) const HEADER_IDENTIFIER_PBE_HEADER: u32 = 0x7A666670;
pub(crate) const HEADER_IDENTIFIER_ENCRYPTION_HEADER: u32 = 0x7A666665;
pub(crate) const HEADER_IDENTIFIER_CHUNK_HEADER: u32 = 0x7A666643;
pub(crate) const HEADER_IDENTIFIER_HASH_HEADER: u32 = 0x7a666668;
pub(crate) const HEADER_IDENTIFIER_HASH_VALUE: u32 = 0x7a666648;

pub(crate) const PBE_KDF_PARAMETERS: u32 = 0x6b646670;

// Encoding keys
pub(crate) const ENCODING_KEY_CASE_NUMBER: &str = "cn";
pub(crate) const ENCODING_KEY_EVIDENCE_NUMBER: &str = "ev";
pub(crate) const ENCODING_KEY_EXAMINER_NAME: &str = "ex";
pub(crate) const ENCODING_KEY_NOTES: &str = "no";
pub(crate) const ENCODING_KEY_ACQISITION_DATE: &str = "ad";

//ZFF File extension
/// the start value for file extensions. a file-extension always starts with a 'z', followed by the segment number (e.g. "z01", "z02", ..., "z99", "z100", ...).
pub const FILE_EXTENSION_START: char = 'z';
/// the file extension for the first segment (which contains the main header also).
pub const FILE_EXTENSION_FIRST_VALUE: &str = "z01";

//Error messages
pub(crate) const FILE_EXTENSION_PARSER_ERROR: &str = "Error while trying to parse extension value";

// Default values
/// the default chunk size as 2^x. This value is 15, so the default chunk size is 2^15 = 32768 bytes.
pub const DEFAULT_CHUNK_SIZE: u8 = 15;