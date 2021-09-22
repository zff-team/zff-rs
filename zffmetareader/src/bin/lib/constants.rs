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

// - args
pub const CLAP_ARG_NAME_OUTPUT_FORMAT: &str = "OUTPUT_FORMAT";
pub const CLAP_ARG_HELP_OUTPUT_FORMAT: &str = "The output format.";
pub const CLAP_ARG_SHORT_OUTPUT_FORMAT: &str = "f";
pub const CLAP_ARG_LONG_OUTPUT_FORMAT: &str = "output-format";
pub const CLAP_ARG_POSSIBLE_VALUES_OUTPUT_FORMAT: [&str; 3] = [CLAP_ARG_VALUE_OUTPUT_FORMAT_TOML, CLAP_ARG_VALUE_OUTPUT_FORMAT_JSON, CLAP_ARG_VALUE_OUTPUT_FORMAT_JSON_PRETTY];
pub const CLAP_ARG_DEFAULT_VALUE_OUTPUT_FORMAT: &'static str = CLAP_ARG_VALUE_OUTPUT_FORMAT_TOML;
pub const CLAP_ARG_VALUE_OUTPUT_FORMAT_TOML: &'static str = "toml";
pub const CLAP_ARG_VALUE_OUTPUT_FORMAT_JSON: &'static str = "json";
pub const CLAP_ARG_VALUE_OUTPUT_FORMAT_JSON_PRETTY: &'static str = "json_pretty";

// Error messages
pub const ERROR_OPEN_INPUT_FILE: &str = "An errror occurred while trying to open the input file.";
pub const ERROR_SERIALIZE_TOML: &str = "An errror occurred while trying to serialize the decoded information to toml format.";
pub const ERROR_SERIALIZE_JSON: &str = "An errror occurred while trying to serialize the decoded information to json format.";
pub const ERROR_SERIALIZE_UNKNOWN_SERIALIZER: &str = "Unknown output format.";
pub const ERROR_UNKNOWN_HEADER: &str = "Could not read header of this file. Are you sure, this is a correct zff file?:\n";
pub const ERROR_FILE_READ: &str = "An error occurred while trying to read the input file.";

pub const EXIT_STATUS_ERROR: i32 = 1;
pub const EXIT_STATUS_SUCCESS: i32 = 0;