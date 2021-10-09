pub const PROGRAM_NAME: &str = env!("CARGO_BIN_NAME");
pub const PROGRAM_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROGRAM_AUTHOR: &str = env!("CARGO_PKG_AUTHORS");
pub const PROGRAM_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

// clap
// - args
pub const CLAP_ARG_NAME_INPUT_FILE: &str = "INPUT_FILE";
pub const CLAP_ARG_HELP_INPUT_FILE: &str = "The input file. This should be your device to dump.";
pub const CLAP_ARG_SHORT_INPUT_FILE: &str = "i";
pub const CLAP_ARG_LONG_INPUT_FILE: &str = "inputfile";

pub const CLAP_ARG_NAME_OUTPUT_FILE: &str = "OUTPUT_FILE";
pub const CLAP_ARG_HELP_OUTPUT_FILE: &str = "The the name/path of the output-file WITHOUT file extension. E.g. \"/home/ph0llux/sda_dump\". File extension will be added automatically.";
pub const CLAP_ARG_SHORT_OUTPUT_FILE: &str = "o";
pub const CLAP_ARG_LONG_OUTPUT_FILE: &str = "outputfile";

pub const CLAP_ARG_NAME_CASE_NUMBER: &str = "CASE_NUMBER";
pub const CLAP_ARG_HELP_CASE_NUMBER: &str = "The case number. This field is OPTIONAL.";
pub const CLAP_ARG_SHORT_CASE_NUMBER: &str = "c";
pub const CLAP_ARG_LONG_CASE_NUMBER: &str = "case-number";

pub const CLAP_ARG_NAME_EVIDENCE_NUMBER: &str = "EVIDENCE_NUMBER";
pub const CLAP_ARG_HELP_EVIDENCE_NUMBER: &str = "The evidence number. This field is OPTIONAL.";
pub const CLAP_ARG_SHORT_EVIDENCE_NUMBER: &str = "e";
pub const CLAP_ARG_LONG_EVIDENCE_NUMBER: &str = "evidence-number";

pub const CLAP_ARG_NAME_EXAMINER_NAME: &str = "EXAMINER_NAME";
pub const CLAP_ARG_HELP_EXAMINER_NAME: &str = "Examiner's name. This field is OPTIONAL.";
pub const CLAP_ARG_SHORT_EXAMINER_NAME: &str = "x";
pub const CLAP_ARG_LONG_EXAMINER_NAME: &str = "examiner-name";

pub const CLAP_ARG_NAME_NOTES: &str = "NOTES";
pub const CLAP_ARG_HELP_NOTES: &str = "Some notes. This field is OPTIONAL.";
pub const CLAP_ARG_SHORT_NOTES: &str = "n";
pub const CLAP_ARG_LONG_NOTES: &str = "notes";

pub const CLAP_ARG_NAME_COMPRESSION_ALGORITHM: &str = "COMPRESSION_ALGORITHM";
pub const CLAP_ARG_HELP_COMPRESSION_ALGORITHM: &str = "sets the compression algorithm. Default is zstd.";
pub const CLAP_ARG_SHORT_COMPRESSION_ALGORITHM: &str = "z";
pub const CLAP_ARG_LONG_COMPRESSION_ALGORITHM: &str = "compression-algorithm";
pub const CLAP_ARG_POSSIBLE_VALUES_COMPRESSION_ALGORITHM: [&str; 3] = ["none", "zstd", "lz4"];

pub const CLAP_ARG_NAME_COMPRESSION_LEVEL: &str = "COMPRESSION_LEVEL";
pub const CLAP_ARG_HELP_COMPRESSION_LEVEL: &str = "sets the compression level. Default is 3. This option doesn't has any effect while using the lz4 compression algorithm.";
pub const CLAP_ARG_SHORT_COMPRESSION_LEVEL: &str = "l";
pub const CLAP_ARG_LONG_COMPRESSION_LEVEL: &str = "compression-level";
pub const CLAP_ARG_POSSIBLE_VALUES_COMPRESSION_LEVEL: [&str; 9] = ["1", "2", "3", "4", "5", "6", "7", "8", "9"];

pub const CLAP_ARG_NAME_SEGMENT_SIZE: &str = "SEGMENT_SIZE";
pub const CLAP_ARG_HELP_SEGMENT_SIZE: &str = "The segment size of the output-file(s). Default is 0 (=the output image will never be splitted into segments).";
pub const CLAP_ARG_SHORT_SEGMENT_SIZE: &str = "s";
pub const CLAP_ARG_LONG_SEGMENT_SIZE: &str = "segment-size";

pub const CLAP_ARG_NAME_CHUNK_SIZE: &str = "CHUNK_SIZE";
pub const CLAP_ARG_HELP_CHUNK_SIZE: &str = "The chunk size. Default is 32kB.";
pub const CLAP_ARG_SHORT_CHUNK_SIZE: &str = "C";
pub const CLAP_ARG_LONG_CHUNK_SIZE: &str = "chunk-size";
pub const CLAP_ARG_POSSIBLE_VALUES_CHUNK_SIZE: [&str; 7] = ["4096", "8192", "16384", "32768", "65536", "131072", "262144"];

pub const CLAP_ARG_NAME_ENCRYPTION_PASSWORD: &str = "ENCRYPTION_PASSWORD";
pub const CLAP_ARG_HELP_ENCRYPTION_PASSWORD: &str = "Sets an encryption password";
pub const CLAP_ARG_SHORT_ENCRYPTION_PASSWORD: &str = "p";
pub const CLAP_ARG_LONG_ENCRYPTION_PASSWORD: &str = "encryption-password";

pub const CLAP_ARG_NAME_PASSWORD_KDF: &str = "PASSWORD_KDF";
pub const CLAP_ARG_HELP_PASSWORD_KDF: &str = "Sets the key derivation function for the password. Default is [pbkdf2_sha256_aes256cbc]";
pub const CLAP_ARG_SHORT_PASSWORD_KDF: &str = "K";
pub const CLAP_ARG_LONG_PASSWORD_KDF: &str = "password-kdf";
pub const CLAP_ARG_POSSIBLE_VALUES_PASSWORD_KDF: [&str; 2] = ["pbkdf2_sha256_aes128cbc", "pbkdf2_sha256_aes256cbc"];

pub const CLAP_ARG_NAME_ENCRYPTION_ALGORITHM: &str = "ENCRYPTION_ALGORITHM";
pub const CLAP_ARG_HELP_ENCRYPTION_ALGORITHM: &str = "Sets the encryption algorithm. Default is [aes256-gcm-siv]";
pub const CLAP_ARG_SHORT_ENCRYPTION_ALGORITHM: &str = "E";
pub const CLAP_ARG_LONG_ENCRYPTION_ALGORITHM: &str = "encryption-algorithm";
pub const CLAP_ARG_POSSIBLE_VALUES_ENCRYPTION_ALGORITHM: [&str; 2] = ["aes128-gcm-siv", "aes256-gcm-siv"];

pub const CLAP_ARG_NAME_ENCRYPTED_HEADER: &str = "ENCRYPTED_HEADER";
pub const CLAP_ARG_HELP_ENCRYPTED_HEADER: &str = "Encrypts the data AND parts of the main header (e.g. the \"description fields, like 'examiner name', 'case number', ...\"";
pub const CLAP_ARG_SHORT_ENCRYPTED_HEADER: &str = "H";
pub const CLAP_ARG_LONG_ENCRYPTED_HEADER: &str = "encrypted-header";

pub const CLAP_ARG_NAME_HASH_ALGORITHM: &str = "HASH_ALGORITHM";
pub const CLAP_ARG_HELP_HASH_ALGORITHM: &str = "This option adds an additional hash algorithm to calculate. You can use this option multiple times.";
pub const CLAP_ARG_SHORT_HASH_ALGORITHM: &str = "d";
pub const CLAP_ARG_LONG_HASH_ALGORITHM: &str = "hash-algorithm";
pub const CLAP_ARG_POSSIBLE_VALUES_HASH_ALGORITHM: [&str; 4] = ["blake2b-512", "sha256", "sha512", "sha3-256"];

pub const CLAP_ARG_NAME_SIGN_DATA: &str = "SIGN_DATA";
pub const CLAP_ARG_HELP_SIGN_DATA: &str = "Sign all data with an autogenerated or given secret EdDSA key.";
pub const CLAP_ARG_SHORT_SIGN_DATA: &str = "S";
pub const CLAP_ARG_LONG_SIGN_DATA: &str = "sign-data";

pub const CLAP_ARG_NAME_SIGN_KEYPAIR: &str = "SIGN_KEYPAIR";
pub const CLAP_ARG_HELP_SIGN_KEYPAIR: &str = "Your secret EdDSA key, base64 formatted.";
pub const CLAP_ARG_SHORT_SIGN_KEYPAIR: &str = "k";
pub const CLAP_ARG_LONG_SIGN_KEYPAIR: &str = "eddsa-keypair";

// default values
pub const DEFAULT_COMPRESSION_LEVEL: u8 = 3;

// - header versions
pub const MAIN_HEADER_VERSION: u8 = 1;
pub const ENCRYPTION_HEADER_VERSION: u8 = 1;
pub const PBE_HEADER_VERSION: u8 = 1;
pub const COMPRESSION_HEADER_VERSION: u8 = 1;
pub const DESCRIPTION_HEADER_VERSION: u8 = 1;
pub const SEGMENT_HEADER_VERSION: u8 = 1;
pub const HASH_HEADER_VERSION: u8 = 1;
pub const HASH_VALUE_HEADER_VERSION: u8 = 1;

//Error messages
pub const ERROR_OPEN_INPUT_FILE: &'static str = "Could not open input file: ";
pub const ERROR_OTHER: &'static str = "An error occurred while trying to write data to segments: ";
pub const ERROR_WRITE_ENCRYPTED_MAIN_HEADER: &'static str = "An error occurred while trying to encode encrypted main header: ";
pub const ERROR_COPY_FILESTREAM_TO_OUTPUT: &'static str = "An I/O error occurred while trying to copy data from input to output file(s): ";
pub const ERROR_PARSE_STR_SEGMENT_SIZE: &'static str = "Could not value as valid segment size: ";
pub const ERROR_ENCRYPT_KEY: &'static str = "Could not encrypt your key with the given password. This is a bug.";
pub const ERROR_UNKNOWN_ENCRYPTION_ALGORITHM: &'static str = "The given encryption algorithm is unknown/not supported by this application. Please use -h to see all supported algorithms.";
pub const ERROR_UNKNOWN_PASSWORD_KDF: &'static str = "The given password key derivation function is unknown/not supported by this application. Please use -h to see all supported algorithms.";
pub const ERROR_GET_HASHTYPES: &'static str = "Unknown hashtype: ";
pub const ERROR_PARSE_KEY: &'static str = "Could not parse your given base64 formatted secret key / keypair.";

pub const EXIT_STATUS_ERROR: i32 = 1;
pub const EXIT_STATUS_SUCCESS: i32 = 0;