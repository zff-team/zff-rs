// - STD
use std::{
    time::{SystemTime,UNIX_EPOCH},
    path::{PathBuf},
    fs::{File, remove_file},
    process::exit,
    io::{Write, Seek, SeekFrom},
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
    SplitHeader,
    HeaderEncoder,
    compress_filestream,
    write_from_compressed_filestream,
    file_extension_next_value,
    FILE_EXTENSION_FIRST_VALUE,
    MINIMUM_SECTOR_SIZE,
};

// - external
use clap::{
    Arg,
    App,
    ArgMatches
};
use rand::Rng;

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
                    .arg(Arg::with_name(CLAP_ARG_NAME_SPLIT_SIZE)
                        .help(CLAP_ARG_HELP_SPLIT_SIZE)
                        .short(CLAP_ARG_SHORT_SPLIT_SIZE)
                        .long(CLAP_ARG_LONG_SPLIT_SIZE)
                        .takes_value(true))
                    .arg(Arg::with_name(CLAP_ARG_NAME_SECTOR_SIZE)
                        .help(CLAP_ARG_HELP_SECTOR_SIZE)
                        .short(CLAP_ARG_SHORT_SECTOR_SIZE)
                        .long(CLAP_ARG_LONG_SECTOR_SIZE)
                        .possible_values(&CLAP_ARG_POSSIBLE_VALUES_SECTOR_SIZE)
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

fn split_header() -> SplitHeader {
    let header_version = SPLIT_HEADER_VERSION;
    let unique_identifier: u64 = rand::thread_rng().gen();
    let split_number = 1;
    let length_of_split = 0;
    SplitHeader::new(header_version, unique_identifier, split_number, length_of_split)
}

fn calculate_split_size(arguments: &ArgMatches) -> u64 {
    //TODO: support human readable split size entries, like 4G or 200M.
    if let Some(value) = arguments.value_of(CLAP_ARG_NAME_SPLIT_SIZE) {
        match value.parse() {
            Ok(val) => val,
            Err(_) => {
                println!("{}{}", ERROR_PARSE_STR_SPLIT_SIZE, value);
                exit(EXIT_STATUS_ERROR);
            }
        }
    } else {
        0
    }
}

fn calculate_sector_size(arguments: &ArgMatches) -> u8 {
    if let Some(value) = arguments.value_of(CLAP_ARG_NAME_SECTOR_SIZE) {
        // Calling .unwrap() is safe here because the possible values are limited
        let value: u32 = value.parse().unwrap();
        (value / 512) as u8
    } else {
        MINIMUM_SECTOR_SIZE as u8
    }
}

fn write_to_output<O>(
    input_path: &PathBuf,
    output_filename: O,
    mut main_header: MainHeader,
    compression_header: CompressionHeader,
    mut split_header: SplitHeader)
where
    O: Into<String>,
{
    let input_file = match File::open(input_path) {
        Ok(file) => file,
        Err(e) => {
            println!("{}{}", ERROR_OPEN_INPUT_FILE, e.to_string());
            exit(EXIT_STATUS_ERROR);
        },
    };
    let output_filename = output_filename.into();
    let split_size = match main_header.split_size() {
        0 => u64::MAX,
        _ => main_header.split_size(),
    };

    let mut input_file = match compress_filestream(
        input_file,
        compression_header.compression_algorithm(),
        compression_header.compression_level()) {
        Ok(stream) => stream,
        Err(_) => {
            println!("{}", ERROR_CREATE_COMPRESS_FILESTREAM);
            exit(EXIT_STATUS_ERROR);
        }
    };

    let header_size = main_header.get_encoded_size();

    let sector_size = main_header.sector_size();

    let first_segment_size = split_size as usize - header_size;
    let mut first_segment_filename = PathBuf::from(&output_filename);
    let mut file_extension = String::from(FILE_EXTENSION_FIRST_VALUE);
    first_segment_filename.set_extension(&file_extension);

    let mut output_file = match File::create(&first_segment_filename) {
        Ok(file) => file,
        Err(_) => {
            println!("{}{}", ERROR_CREATE_OUTPUT_FILE, &first_segment_filename.to_string_lossy());
            exit(EXIT_STATUS_ERROR);
        }
    };

    match output_file.write(&main_header.encode_directly()) {
        Ok(_) => (),
        Err(e) => {
            println!("{}{}", ERROR_WRITE_MAIN_HEADER, e.to_string());
            exit(EXIT_STATUS_ERROR);
        }
    };
    
    let mut written_bytes = match write_from_compressed_filestream(
        &mut input_file,
        &mut output_file,
        first_segment_size,
        sector_size) {
        Ok(val) => val,
        Err(e) => {
            println!("{}{}", ERROR_COPY_FILESTREAM_TO_OUTPUT, e.to_string());
            exit(EXIT_STATUS_ERROR);
        },
    };

    split_header.set_length_of_split(written_bytes);
    main_header.set_split_header(split_header.clone());

    loop {
        let segment_split_header = split_header.next_header();
        file_extension = match file_extension_next_value(&file_extension) {
            Ok(val) => val,
            Err(e) => {
                println!("{}{}", ERROR_SET_FILE_EXTENSION, e.to_string());
                exit(EXIT_STATUS_ERROR);
            }
        };
        let mut segment_filename = PathBuf::from(&output_filename);
        segment_filename.set_extension(&file_extension);
        let mut output_file = match File::create(&segment_filename) {
            Ok(file) => file,
            Err(_) => {
                println!("{}{}", ERROR_CREATE_OUTPUT_FILE, &segment_filename.to_string_lossy());
                exit(EXIT_STATUS_ERROR);
            }
        };

        match output_file.write(&segment_split_header.encode_directly()) {
            Ok(_) => (),
            Err(_) => {
                println!("{}{}", ERROR_WRITE_SPLIT_HEADER, segment_filename.to_string_lossy());
                exit(EXIT_STATUS_ERROR);
            }
        };

        let written_bytes_in_segment = match write_from_compressed_filestream(
            &mut input_file,
            &mut output_file,
            split_size as usize,
            sector_size) {

            Ok(val) => val,
            Err(e) => {
                println!("{}{}", ERROR_COPY_FILESTREAM_TO_OUTPUT, e.to_string());
                exit(EXIT_STATUS_ERROR);
            }
        };
        if written_bytes_in_segment == 0 {
            let _ = remove_file(segment_filename);
            break;
        } else {
            written_bytes += written_bytes_in_segment
        }
    }

    //rewrite main_header with the correct number of bytes of the COMPRESSED data.
    main_header.set_length_of_data(written_bytes);
    match output_file.seek(SeekFrom::Start(0)) {
        Ok(_) => (),
        Err(e) => {
            println!("{}{}", ERROR_REWRITE_MAIN_HEADER, e.to_string());
            exit(EXIT_STATUS_ERROR);
        }
    }
    match output_file.write(&main_header.encode_directly()) {
        Ok(_) => (),
        Err(e) => {
            println!("{}{}", ERROR_REWRITE_MAIN_HEADER, e.to_string());
            exit(EXIT_STATUS_ERROR);
        }
    };
}

fn main() {
	let arguments = arguments();
    let compression_header = compression_header(&arguments);
    let description_header = description_header(&arguments);
    let split_size = calculate_split_size(&arguments);
    let sector_size = calculate_sector_size(&arguments);
    let split_header = split_header();

    // Calling .unwrap() is safe here because the arguments are *required*.
    let input_path = PathBuf::from(arguments.value_of(CLAP_ARG_NAME_INPUT_FILE).unwrap());
    let output_filename = arguments.value_of(CLAP_ARG_NAME_OUTPUT_FILE).unwrap();

    let main_header = MainHeader::new(
        MAIN_HEADER_VERSION,
        compression_header.clone(),
        description_header,
        sector_size,
        split_size,
        split_header.clone(),
        0);

    write_to_output(&input_path, output_filename, main_header, compression_header, split_header);
}