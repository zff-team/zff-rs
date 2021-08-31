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
pub const CLAP_ARG_POSSIBLE_VALUES_COMPRESSION_ALGORITHM: [&str; 2] = ["none", "zstd"];

pub const CLAP_ARG_NAME_COMPRESSION_LEVEL: &str = "COMPRESSION_LEVEL";
pub const CLAP_ARG_HELP_COMPRESSION_LEVEL: &str = "sets the compression level. Default is 3.";
pub const CLAP_ARG_SHORT_COMPRESSION_LEVEL: &str = "l";
pub const CLAP_ARG_LONG_COMPRESSION_LEVEL: &str = "compression-level";
pub const CLAP_ARG_POSSIBLE_VALUES_COMPRESSION_LEVEL: [&str; 9] = ["1", "2", "3", "4", "5", "6", "7", "8", "9"];

pub const CLAP_ARG_NAME_SPLIT_SIZE: &str = "SPLIT_SIZE";
pub const CLAP_ARG_HELP_SPLIT_SIZE: &str = "The split size of the output-file(s). Default is 0 (=the output image will never be splitted).";
pub const CLAP_ARG_SHORT_SPLIT_SIZE: &str = "s";
pub const CLAP_ARG_LONG_SPLIT_SIZE: &str = "split-size";

pub const CLAP_ARG_NAME_SECTOR_SIZE: &str = "SECTOR_SIZE";
pub const CLAP_ARG_HELP_SECTOR_SIZE: &str = "The sector size. Default is 512 bytes.";
pub const CLAP_ARG_SHORT_SECTOR_SIZE: &str = "S";
pub const CLAP_ARG_LONG_SECTOR_SIZE: &str = "sector-size";
pub const CLAP_ARG_POSSIBLE_VALUES_SECTOR_SIZE: [&str; 8] = ["512", "1024", "2048", "4096", "8192", "16384", "32768", "65536"];

// - header versions
pub const MAIN_HEADER_VERSION: u8 = 1;
pub const COMPRESSION_HEADER_VERSION: u8 = 1;
pub const DESCRIPTION_HEADER_VERSION: u8 = 1;
pub const SPLIT_HEADER_VERSION: u8 = 1;

// compression
pub const DEFAULT_COMPRESSION_LEVEL: u8 = 3;

//Error messages
pub const ERROR_OPEN_INPUT_FILE: &'static str = "Could not open input file: ";
pub const ERROR_CREATE_OUTPUT_FILE: &'static str = "Could not create output file: ";
pub const ERROR_WRITE_MAIN_HEADER: &'static str = "Could not write main header to file: ";
pub const ERROR_WRITE_SPLIT_HEADER: &'static str = "Could not write split header to file: ";
pub const ERROR_CREATE_COMPRESS_FILESTREAM: &'static str = "Could not create a compression stream around the input file. Maybe you want to try to dump uncompressed?";
pub const ERROR_COPY_FILESTREAM_TO_OUTPUT: &'static str = "An I/O error occurred while trying to copy data from input to output file(s): ";
pub const ERROR_REWRITE_MAIN_HEADER: &'static str = "An error occurred while trying to rewrite the main header to the output file. The written data length specified is not correctly listed in the header: ";
pub const ERROR_PARSE_STR_SPLIT_SIZE: &'static str = "Could not value as valid split size: ";
pub const ERROR_SET_FILE_EXTENSION: &'static str = "Could not set file extension for next part of image: ";

pub const EXIT_STATUS_ERROR: i32 = 1;