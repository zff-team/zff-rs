use redb::TableDefinition;

use ed25519_dalek::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

// identifier: magic bytes
/// The identifier of the encrypted variant of the [MainHeader](crate::header::version1::MainHeader).
pub const HEADER_IDENTIFIER_ENCRYPTED_MAIN_HEADER: u32 = 0x7A666645;
/// The identifier of the [DescriptionHeader](crate::header::DescriptionHeader).
pub const HEADER_IDENTIFIER_DESCRIPTION_HEADER: u32 = 0x7A666664;
/// The identifier of the [SegmentHeader](crate::header::SegmentHeader).
pub const HEADER_IDENTIFIER_SEGMENT_HEADER: u32 = 0x7A66666D;
/// The identifier of the [CompressionHeader](crate::header::CompressionHeader).
pub const HEADER_IDENTIFIER_COMPRESSION_HEADER: u32 = 0x7A666663;
/// The identifier of the [PBEHeader](crate::header::PBEHeader).
pub const HEADER_IDENTIFIER_PBE_HEADER: u32 = 0x7A666670;
/// The identifier of the [EncryptionHeader](crate::header::EncryptionHeader).
pub const HEADER_IDENTIFIER_ENCRYPTION_HEADER: u32 = 0x7A666665;
/// The identifier of the [ChunkHeader](crate::header::ChunkHeader).
pub const HEADER_IDENTIFIER_CHUNK_HEADER: u32 = 0x7A666643;
/// The identifier of the [HashHeader](crate::header::HashHeader).
pub const HEADER_IDENTIFIER_HASH_HEADER: u32 = 0x7A666668;
/// The identifier of the [HashValue](crate::header::HashValue).
pub const HEADER_IDENTIFIER_HASH_VALUE: u32 = 0x7A666648;
/// The identifier of the [ObjectHeader](crate::header::ObjectHeader).
pub const HEADER_IDENTIFIER_OBJECT_HEADER: u32 = 0x7A66664F;
/// The identifier of the [FileHeader](crate::header::FileHeader).
pub const HEADER_IDENTIFIER_FILE_HEADER: u32 = 0x7A666666;
/// The identifier of the [ChunkMap](crate::header::ChunkMap).
pub const HEADER_IDENTIFIER_CHUNK_MAP: u32 = 0x7a666678;

pub(crate) const FOOTER_IDENTIFIER_SEGMENT_FOOTER: u32 = 0x7A666646;
pub(crate) const FOOTER_IDENTIFIER_MAIN_FOOTER: u32 = 0x7A66664D;
pub(crate) const FOOTER_IDENTIFIER_OBJECT_FOOTER_PHYSICAL: u32 = 0x7A666650;
pub(crate) const FOOTER_IDENTIFIER_OBJECT_FOOTER_LOGICAL: u32 = 0x7A66664C;
pub(crate) const FOOTER_IDENTIFIER_FILE_FOOTER: u32 = 0x7A666649;

pub(crate) const PBE_KDF_PARAMETERS_PBKDF2: u32 = 0x6B646670;
pub(crate) const PBE_KDF_PARAMETERS_SCRYPT: u32 = 0x6b646673;
pub(crate) const PBE_KDF_PARAMETERS_ARGON2ID: u32 = 0x6b646661;

// Encoding keys
pub(crate) const ENCODING_KEY_CASE_NUMBER: &str = "cn";
pub(crate) const ENCODING_KEY_EVIDENCE_NUMBER: &str = "ev";
pub(crate) const ENCODING_KEY_EXAMINER_NAME: &str = "ex";
pub(crate) const ENCODING_KEY_NOTES: &str = "no";
pub(crate) const ENCODING_KEY_ACQISITION_START: &str = "as";
pub(crate) const ENCODING_KEY_ACQISITION_END: &str = "ae";
pub(crate) const ENCODING_KEY_DESCRIPTION_NOTES: &str = "dn";

// chunk header flags
pub(crate) const ERROR_FLAG_VALUE: u8 = 1<<0;
pub(crate) const COMPRESSION_FLAG_VALUE: u8 = 1<<1;
pub(crate) const SAME_BYTES_FLAG_VALUE: u8 = 1<<2;
pub(crate) const DUPLICATION_FLAG_VALUE: u8 = 1<<3;
pub(crate) const ENCRYPTION_FLAG_VALUE: u8 = 1<<4;

// object header flags
pub(crate) const ENCRYPT_OBJECT_FLAG_VALUE: u8 = 1<<0;
pub(crate) const SIGN_HASH_FLAG_VALUE: u8 = 1<<1;
pub(crate) const PASSIVE_OBJECT_FLAG_VALUE: u8 = 1<<2;

// - Error messages
pub(crate) const ERROR_HEADER_DECODER_UNKNOWN_HASH_TYPE: &str = "Unknown hash type value.";
pub(crate) const ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER_KDF: &str = "The read identifier does not match to any known KDF header identifier.";
pub(crate) const ERROR_HEADER_DECODER_UNKNOWN_PBE_SCHEME: &str = "Unknown PBEncryption scheme value.";
pub(crate) const ERROR_HEADER_DECODER_UNKNOWN_KDF_SCHEME: &str = "Unknown KDF scheme value.";
pub(crate) const ERROR_HEADER_DECODER_UNKNOWN_ENCRYPTION_ALGORITHM: &str = "Unknown encryption algorithm value.";
pub(crate) const FILE_EXTENSION_PARSER_ERROR: &str = "Error while trying to parse extension value";
pub(crate) const ERROR_HEADER_DECODER_HEADER_LENGTH: &str = "Unable to read header length from given data.";
pub(crate) const ERROR_HEADER_DECODER_KEY_POSITION: &str = "Key not in position.";
pub(crate) const ERROR_HEADER_DECODER_COMPRESSION_ALGORITHM: &str = "unknown compression algorithm value";
pub(crate) const ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER: &str = "The read identifier does not match the header identifier.";
pub(crate) const ERROR_MISSING_SEGMENT_MAIN_FOOTER: &str = "A segment with a valid zff main footer is missing.";
pub(crate) const ERROR_MISSING_OBJECT_HEADER_IN_SEGMENT: &str = "Missing object header in segment with following object number: ";
pub(crate) const ERROR_MISSING_OBJECT_FOOTER_IN_SEGMENT: &str = "Missing object footer in segment with following object number: ";
pub(crate) const ERROR_MISSING_FILE_NUMBER: &str = "Missing filenumber: ";
pub(crate) const ERROR_MISMATCH_ZFF_VERSION: &str = "mismatch zff version";
pub(crate) const ERROR_INVALID_OBJECT_TYPE_FLAG_VALUE: &str = "Invalid object type flag value:";
pub(crate) const ERROR_INVALID_OPTION_ZFFEXTEND: &str = "Extend container";
pub(crate) const ERROR_INVALID_OPTION_ZFFCREATE: &str = "Create new container";
pub(crate) const ERROR_LAST_GREATER_FIRST: &str = "First chunk number is greater than last chunk number. This is invalid.";

pub(crate) const ERROR_ZFFREADER_SEGMENT_NOT_FOUND: &str = "The segment of the chunk was not found.";

pub(crate) const ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION: &str = "Unseekable position (position is negative).";

pub(crate) const ERROR_ZFFREADER_MISSING_OBJECT: &str = "Missing object number in zffreader: ";
pub(crate) const ERROR_ZFFREADER_MISSING_FILE: &str = "Missing file number in zffreader: ";

// Default values
pub(crate) const DEFAULT_LENGTH_HEADER_IDENTIFIER: usize = 4;
pub(crate) const DEFAULT_LENGTH_VALUE_HEADER_LENGTH: usize = 8;
/// The number of the first object in a zff container.
pub const INITIAL_OBJECT_NUMBER: u64 = 1;

/// The default compression ratio threshold
pub const DEFAULT_COMPRESSION_RATIO_THRESHOLD: &str = "1.05";

/// the default key length of a public signature key
pub const ED25519_DALEK_PUBKEY_LEN: usize = PUBLIC_KEY_LENGTH;
/// the default length of an ed25519 signature
pub const ED25519_DALEK_SIGNATURE_LEN: usize = SIGNATURE_LENGTH;

//ZFF File extension
/// the start value for file extensions. a file-extension always starts with a 'z', followed by the segment number (e.g. "z01", "z02", ..., "z99", "z100", ...).
pub const FILE_EXTENSION_START: char = 'z';
/// the file extension for the first segment (which contains the main header also).
pub const FILE_EXTENSION_INITIALIZER: &str = "z00";

// default versions
/// current header version for the [ChunkHeader](crate::header::ChunkHeader).
pub const DEFAULT_HEADER_VERSION_CHUNK_HEADER: u8 = 2;
/// current header version for the [HashValue](crate::header::HashValue) structure.
pub const DEFAULT_HEADER_VERSION_HASH_VALUE_HEADER: u8 = 2;
/// current header version for the [HashHeader](crate::header::HashHeader).
pub const DEFAULT_HEADER_VERSION_HASH_HEADER: u8 = 2;
/// current header version for the [SegmentHeader](crate::header::SegmentHeader).
pub const DEFAULT_HEADER_VERSION_SEGMENT_HEADER: u8 = 3;
/// current header version for the [CompressionHeader](crate::header::CompressionHeader).
pub const DEFAULT_HEADER_VERSION_COMPRESSION_HEADER: u8 = 1;
/// current header version for the [DescriptionHeader](crate::header::DescriptionHeader).
pub const DEFAULT_HEADER_VERSION_DESCRIPTION_HEADER: u8 = 2;
/// current header version for the [PBEHeader](crate::header::PBEHeader).
pub const DEFAULT_HEADER_VERSION_PBE_HEADER: u8 = 2;
/// current header version for the [EncryptionHeader](crate::header::EncryptionHeader).
pub const DEFAULT_HEADER_VERSION_ENCRYPTION_HEADER: u8 = 2;
/// current header version for the [MainHeader](crate::header::MainHeader).
pub const DEFAULT_HEADER_VERSION_MAIN_HEADER: u8 = 2;
/// current header version for the [FileHeader](crate::header::FileHeader).
pub const DEFAULT_HEADER_VERSION_FILE_HEADER: u8 = 2;
/// current header version for the [ObjectHeader](crate::header::ObjectHeader).
pub const DEFAULT_HEADER_VERSION_OBJECT_HEADER: u8 = 2;
/// current header version for the [ChunkMap](crate::header::ChunkMap) structure.
pub const DEFAULT_HEADER_VERSION_CHUNK_MAP: u8 = 1;

/// current footer version for the [ObjectFooterPhysical](crate::footer::ObjectFooterPhysical).
pub const DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_PHYSICAL: u8 = 1;
/// current footer version for the [ObjectFooterLogical](crate::header::ObjectFooterLogical).
pub const DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_LOGICAL: u8 = 1;
/// current footer version for the [SegmentFooter](crate::header::SegmentFooter).
pub const DEFAULT_FOOTER_VERSION_SEGMENT_FOOTER: u8 = 2;
/// current footer version for the [MainFooter](crate::header::MainFooter).
pub const DEFAULT_FOOTER_VERSION_MAIN_FOOTER: u8 = 1;
/// current footer version for the [FileFooter](crate::header::FileFooter).
pub const DEFAULT_FOOTER_VERSION_FILE_FOOTER: u8 = 2;

/// The default header signature length.
pub const HEADER_SIGNATURE_LENGTH: usize = 4;
/// The default size of the field "header length".
pub const HEADER_LENGTH_LENGTH: usize = 8;
/// The default size of the field "header version".
pub const HEADER_VERSION_LENGTH: usize = 1;
/// The default chunkmap size
pub const DEFAULT_CHUNKMAP_SIZE: u64 = 32768;


// file metadata extended values
#[cfg(target_os = "linux")]
pub(crate) const METADATA_EXT_KEY_DEVID: &str = "devid";
#[cfg(target_os = "linux")]
pub(crate) const METADATA_EXT_KEY_INODE: &str = "inode";
#[cfg(target_os = "linux")]
pub(crate) const METADATA_EXT_KEY_MODE: &str = "mode";
#[cfg(target_os = "linux")]
pub(crate) const METADATA_EXT_KEY_UID: &str = "uid";
#[cfg(target_os = "linux")]
pub(crate) const METADATA_EXT_KEY_GID: &str = "gid";
#[cfg(target_os = "windows")]
pub(crate) const METADATA_EXT_DW_FILE_ATTRIBUTES: &str = "dwFileAttributes";

pub(crate) const METADATA_ATIME: &str = "atime";
pub(crate) const METADATA_MTIME: &str = "mtime";
pub(crate) const METADATA_CTIME: &str = "ctime";
pub(crate) const METADATA_BTIME: &str = "btime";


// - ChunkMap
pub const CHUNK_MAP_TABLE: TableDefinition<&[u8; 32], u64> = TableDefinition::new("map");
pub const PRELOADED_CHUNK_MAP_TABLE: TableDefinition<u64, u64> = TableDefinition::new("preloaded_map");

// - Encryption parameters
pub(crate) const SCRYPT_DERIVED_KEY_LENGTH_AES_128: usize = 16; // in bytes
pub(crate) const SCRYPT_DERIVED_KEY_LENGTH_AES_256: usize = 32; // in bytes