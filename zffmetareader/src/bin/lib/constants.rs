pub(crate) const PROGRAM_NAME: &str = env!("CARGO_BIN_NAME");
pub(crate) const PROGRAM_VERSION: &str = env!("CARGO_PKG_VERSION");
pub(crate) const PROGRAM_AUTHOR: &str = env!("CARGO_PKG_AUTHORS");
pub(crate) const PROGRAM_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

// clap
// - args
pub(crate) const CLAP_ARG_NAME_INPUT_FILE: &str = "INPUT_FILE";
pub(crate) const CLAP_ARG_HELP_INPUT_FILE: &str = "The input file. This should be your device to dump.";
pub(crate) const CLAP_ARG_SHORT_INPUT_FILE: &str = "i";
pub(crate) const CLAP_ARG_LONG_INPUT_FILE: &str = "inputfile";

pub(crate) const CLAP_ARG_NAME_OUTPUT_FORMAT: &str = "OUTPUT_FORMAT";
pub(crate) const CLAP_ARG_HELP_OUTPUT_FORMAT: &str = "The output format.";
pub(crate) const CLAP_ARG_SHORT_OUTPUT_FORMAT: &str = "f";
pub(crate) const CLAP_ARG_LONG_OUTPUT_FORMAT: &str = "output-format";
pub(crate) const CLAP_ARG_POSSIBLE_VALUES_OUTPUT_FORMAT: [&str; 3] = [CLAP_ARG_VALUE_OUTPUT_FORMAT_TOML, CLAP_ARG_VALUE_OUTPUT_FORMAT_JSON, CLAP_ARG_VALUE_OUTPUT_FORMAT_JSON_PRETTY];
pub(crate) const CLAP_ARG_DEFAULT_VALUE_OUTPUT_FORMAT: &'static str = CLAP_ARG_VALUE_OUTPUT_FORMAT_TOML;
pub(crate) const CLAP_ARG_VALUE_OUTPUT_FORMAT_TOML: &'static str = "toml";
pub(crate) const CLAP_ARG_VALUE_OUTPUT_FORMAT_JSON: &'static str = "json";
pub(crate) const CLAP_ARG_VALUE_OUTPUT_FORMAT_JSON_PRETTY: &'static str = "json_pretty";

pub(crate) const CLAP_ARG_NAME_PASSWORD: &str = "PASSWORD";
pub(crate) const CLAP_ARG_HELP_PASSWORD: &str = "The password, if the file is an encrypted main header";
pub(crate) const CLAP_ARG_SHORT_PASSWORD: &str = "p";
pub(crate) const CLAP_ARG_LONG_PASSWORD: &str = "password";

pub(crate) const CLAP_ARG_NAME_VERIFY: &str = "VERIFY";
pub(crate) const CLAP_ARG_HELP_VERIFY: &str = "Verify the image";
pub(crate) const CLAP_ARG_SHORT_VERIFY: &str = "V";
pub(crate) const CLAP_ARG_LONG_VERIFY: &str = "verify";

pub(crate) const CLAP_ARG_NAME_PUBKEYFILE: &str = "PUBKEYFILE";
pub(crate) const CLAP_ARG_HELP_PUBKEYFILE: &str = "The path to the file which contains the public key.";
pub(crate) const CLAP_ARG_SHORT_PUBKEYFILE: &str = "k";
pub(crate) const CLAP_ARG_LONG_PUBKEYFILE: &str = "publickey-file";

// Error messages
pub(crate) const ERROR_OPEN_INPUT_FILE: &str = "An error occurred while trying to open the input file.";
pub(crate) const ERROR_UNREADABLE_INPUT_DIR: &str = "Could not read the directory of the given zff file: ";
pub(crate) const ERROR_OPEN_FILE_PUBKEY: &str = "An error occurred while trying to open the file containing the public key: ";
pub(crate) const ERROR_READ_PUBKEY: &str = "An error occurred while trying to read the public key: ";
pub(crate) const ERROR_UNDETERMINABLE_INPUT_DIR: &str = "could not determine input path!";
pub(crate) const ERROR_SERIALIZE_TOML: &str = "An error occurred while trying to serialize the decoded information to toml format.";
pub(crate) const ERROR_SERIALIZE_JSON: &str = "An error occurred while trying to serialize the decoded information to json format.";
pub(crate) const ERROR_SERIALIZE_UNKNOWN_SERIALIZER: &str = "Unknown output format.";
pub(crate) const ERROR_UNKNOWN_HEADER: &str = "Could not read header of this file. This file is not a well formatted zff file.";
pub(crate) const ERROR_FILE_READ: &str = "An error occurred while trying to read the input file.";
pub(crate) const ERROR_MISSING_ENCRYPTION_KEY: &str = "Zff file(s) are encrypted: You should enter the password by using the -p argument.";
pub(crate) const ERROR_DECODE_BASE64_PUBKEY: &str = "An error occurred while trying to decode the public key: ";
pub(crate) const ERROR_START_VERIFICATION_PROCESS: &str = "An error occurred while trying to start the verification process: ";
pub(crate) const ERROR_EMPTY_FILE: &str = "File is empty!";

pub(crate) const ERROR_PARSE_MAIN_HEADER: &str = "An error occurred while trying to parse the main header: ";
pub(crate) const ERROR_PARSE_ENCRYPTED_MAIN_HEADER: &str = "An error occurred while trying to parse the (encrypted) main header: ";
pub(crate) const ERROR_PARSE_SEGMENT_HEADER: &str = "An error occurred while trying to parse the segment header: ";
pub(crate) const ERROR_NO_PASSWORD: &str = "The header of this file is encrypted, so you have to pass the correct password by adding -p PASSWORD.";
pub(crate) const ERROR_WRONG_PASSWORD: &str = "Incorrect password";

pub(crate) const EXIT_STATUS_ERROR: i32 = 1;
pub(crate) const EXIT_STATUS_SUCCESS: i32 = 0;

// special paths
pub(crate) const PWD: &'static str = ".";


// verifier results
pub(crate) const VERIFIER_RESULT_SUCCESS: &'static str = "The data of the image is valid";
pub(crate) const VERIFIER_RESULT_CORRUPTION_FOUND: &'static str = "Corrupted data chunks found. The following chunks (listet by chunk numbers) are NOT valid:";
pub(crate) const VERIFIER_RESULT_ERROR: &'static str = "An error occurred while trying to verify the data: ";