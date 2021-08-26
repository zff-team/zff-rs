// - STD
use std::{
    time::{SystemTime,UNIX_EPOCH},
    path::{PathBuf},
    fs::{File},
    process::exit,
    io::{Write},
};

// - extern crates
extern crate clap;

// - modules
mod lib;

// - internal
use crate::lib::*;
use zff::{
    MainHeader,
    DescriptionHeader,
    CompressionHeader,
    CompressionAlgorithm,
    HeaderEncoder,
};

// - external
use clap::{
    Arg,
    App,
    ArgMatches
};

fn arguments() -> ArgMatches<'static> {
    let matches = App::new(PROGRAM_NAME)
                    .version(PROGRAM_VERSION)
                    .author(PROGRAM_AUTHOR)
                    .about(PROGRAM_DESCRIPTION)
                    .arg(Arg::with_name(CLAP_ARG_NAME_INPUT_FILE)
                        .help(CLAP_ARG_HELP_INPUT_FILE)
                        .short(CLAP_ARG_SHORT_INPUT_FILE)
                        .long(CLAP_ARG_LONG_INPUT_FILE)
                        .required(true)
                        .takes_value(true))
                    .arg(Arg::with_name(CLAP_ARG_NAME_OUTPUT_FILE)
                        .help(CLAP_ARG_HELP_OUTPUT_FILE)
                        .short(CLAP_ARG_SHORT_OUTPUT_FILE)
                        .long(CLAP_ARG_LONG_OUTPUT_FILE)
                        .required(true)
                        .takes_value(true))
                    .arg(Arg::with_name(CLAP_ARG_NAME_COMPRESSION_ALGORITHM)
                        .help(CLAP_ARG_HELP_COMPRESSION_ALGORITHM)
                        .short(CLAP_ARG_SHORT_COMPRESSION_ALGORITHM)
                        .long(CLAP_ARG_LONG_COMPRESSION_ALGORITHM)
                        .possible_values(&CLAP_ARG_POSSIBLE_VALUES_COMPRESSION_ALGORITHM)
                        .takes_value(true))
                    .arg(Arg::with_name(CLAP_ARG_NAME_COMPRESSION_LEVEL)
                        .help(CLAP_ARG_HELP_COMPRESSION_LEVEL)
                        .short(CLAP_ARG_SHORT_COMPRESSION_LEVEL)
                        .long(CLAP_ARG_LONG_COMPRESSION_LEVEL)
                        .possible_values(&CLAP_ARG_POSSIBLE_VALUES_COMPRESSION_LEVEL)
                        .takes_value(true))
                    .arg(Arg::with_name(CLAP_ARG_NAME_CASE_NUMBER)
                        .help(CLAP_ARG_HELP_CASE_NUMBER)
                        .short(CLAP_ARG_SHORT_CASE_NUMBER)
                        .long(CLAP_ARG_LONG_CASE_NUMBER)
                        .takes_value(true))
                    .arg(Arg::with_name(CLAP_ARG_NAME_EVIDENCE_NUMBER)
                        .help(CLAP_ARG_HELP_EVIDENCE_NUMBER)
                        .short(CLAP_ARG_SHORT_EVIDENCE_NUMBER)
                        .long(CLAP_ARG_LONG_EVIDENCE_NUMBER)
                        .takes_value(true))
                    .arg(Arg::with_name(CLAP_ARG_NAME_EXAMINER_NAME)
                        .help(CLAP_ARG_HELP_EXAMINER_NAME)
                        .short(CLAP_ARG_SHORT_EXAMINER_NAME)
                        .long(CLAP_ARG_LONG_EXAMINER_NAME)
                        .takes_value(true))
                    .arg(Arg::with_name(CLAP_ARG_NAME_NOTES)
                        .help(CLAP_ARG_HELP_NOTES)
                        .short(CLAP_ARG_SHORT_NOTES)
                        .long(CLAP_ARG_LONG_NOTES)
                        .takes_value(true))
                    .get_matches();
    matches
}

fn compression_header(arguments: &ArgMatches) -> CompressionHeader {
    let compression_algorithm = match arguments.value_of(CLAP_ARG_NAME_COMPRESSION_ALGORITHM) {
        None => CompressionAlgorithm::Zstd,
        Some(algo) => CompressionAlgorithm::from(algo),
    };
    let compression_level = match arguments.value_of(CLAP_ARG_NAME_COMPRESSION_LEVEL) {
        None => DEFAULT_COMPRESSION_LEVEL,
        Some(level) => level.parse().unwrap_or(DEFAULT_COMPRESSION_LEVEL),
    };
    CompressionHeader::new(COMPRESSION_HEADER_VERSION, compression_algorithm, compression_level)
}

fn description_header(arguments: &ArgMatches) -> DescriptionHeader {
    let mut description_header = DescriptionHeader::new_empty(DESCRIPTION_HEADER_VERSION);
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => description_header.set_acquisition_date(now.as_secs()),
        Err(_) => ()
    };
    if let Some(value) = arguments.value_of(CLAP_ARG_NAME_CASE_NUMBER) {
        description_header.set_case_number(value);
    };
    if let Some(value) = arguments.value_of(CLAP_ARG_NAME_EVIDENCE_NUMBER) {
        description_header.set_evidence_number(value);
    };
    if let Some(value) = arguments.value_of(CLAP_ARG_NAME_EXAMINER_NAME) {
        description_header.set_examiner_name(value);
    };
    if let Some(value) = arguments.value_of(CLAP_ARG_NAME_NOTES) {
        description_header.set_notes(value);
    };
    description_header
}

fn main() {
	let arguments = arguments();
    let compression_header = compression_header(&arguments);
    let description_header = description_header(&arguments);

    // Calling .unwrap() is safe here because the arguments are *required*.
    let input_path = PathBuf::from(arguments.value_of(CLAP_ARG_NAME_INPUT_FILE).unwrap());
    let input_file = match File::open(input_path) {
        Ok(file) => file,
        Err(e) => {
            println!("{}{}", ERROR_OPEN_INPUT_FILE, e.to_string());
            exit(1);
        },
    };
    let input_file_len = match input_file.metadata() {
        Ok(metadata) => metadata.len(),
        Err(e) => {
            println!("{}{}", ERROR_READ_METADATA_INPUT_FILE, e.to_string());
            exit(1);
        }
    };
    let output_filename = arguments.value_of(CLAP_ARG_NAME_OUTPUT_FILE).unwrap();
    let main_header = MainHeader::new(MAIN_HEADER_VERSION, compression_header, description_header, input_file_len);

    let mut output_path = PathBuf::from(output_filename);
    output_path.set_extension("z01"); //TODO

    let mut output_file = match File::create(&output_path) {
        Ok(file) => file,
        Err(e) => {
            println!("{}{}; {}", ERROR_CREATE_OUTPUT_FILE, output_path.to_string_lossy(), e.to_string());
            exit(1);
        }
    };
    match output_file.write(&main_header.encode_directly()) {
        Ok(_) => (),
        Err(e) => {
            println!("{}{}", ERROR_WRITE_MAIN_HEADER, e.to_string());
            exit(1);
        }
    };
}