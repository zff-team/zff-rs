// identifier: magic bytes
pub const HEADER_IDENTIFIER_MAIN_HEADER: u32 = 0x7A66666d;
pub const HEADER_IDENTIFIER_DESCRIPTION_HEADER: u32 = 0x7A666664;
pub const HEADER_IDENTIFIER_SPLIT_HEADER: u32 = 0x7A666673;
pub const HEADER_IDENTIFIER_COMPRESSION_HEADER: u32 = 0x7A666663;
pub const HEADER_IDENTIFIER_PBE_HEADER: u32 = 0x7A666670;
pub const HEADER_IDENTIFIER_ENCRYPTION_HEADER: u32 = 0x7A666665;

pub const PBE_KDF_PARAMETERS: u32 = 0x6b646670;

// Encoding keys
pub const ENCODING_KEY_CASE_NUMBER: &str = "cn";
pub const ENCODING_KEY_EVIDENCE_NUMBER: &str = "ev";
pub const ENCODING_KEY_EXAMINER_NAME: &str = "ex";
pub const ENCODING_KEY_NOTES: &str = "no";
pub const ENCODING_KEY_ACQISITION_DATE: &str = "ad";

//ZFF File extension
pub const FILE_EXTENSION_START: char = 'z';
pub const FILE_EXTENSION_FIRST_VALUE: &str = "z01";

//Error messages
pub const FILE_EXTENSION_PARSER_ERROR: &str = "Error while trying to parse extension value";


//Other
pub const MINIMUM_SECTOR_SIZE: usize = 512;