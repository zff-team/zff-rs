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
    PBEHeader,
    KDFParameters,
    PBKDF2SHA256Parameters,
    EncryptionHeader,
    EncryptionAlgorithm,
    DescriptionHeader,
    CompressionHeader,
    CompressionAlgorithm,
    SplitHeader,
    ChunkHeader,
    HeaderEncoder,
    KDFScheme,
    PBEScheme,
    write_segment,
    file_extension_next_value,
    Encryption,
    FILE_EXTENSION_FIRST_VALUE,
    DEFAULT_CHUNK_SIZE,
};

// - external
use clap::{
    Arg,
    App,
    ArgMatches
};
use rand_core::{RngCore, OsRng};

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
                    .arg(Arg::with_name(CLAP_ARG_NAME_CHUNK_SIZE)
                        .help(CLAP_ARG_HELP_CHUNK_SIZE)
                        .short(CLAP_ARG_SHORT_CHUNK_SIZE)
                        .long(CLAP_ARG_LONG_CHUNK_SIZE)
                        .possible_values(&CLAP_ARG_POSSIBLE_VALUES_CHUNK_SIZE)
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
                    .arg(Arg::with_name(CLAP_ARG_NAME_ENCRYPTION_PASSWORD)
                        .help(CLAP_ARG_HELP_ENCRYPTION_PASSWORD)
                        .short(CLAP_ARG_SHORT_ENCRYPTION_PASSWORD)
                        .long(CLAP_ARG_LONG_ENCRYPTION_PASSWORD)
                        .takes_value(true))
                    .arg(Arg::with_name(CLAP_ARG_NAME_PASSWORD_KDF)
                        .help(CLAP_ARG_HELP_PASSWORD_KDF)
                        .short(CLAP_ARG_SHORT_PASSWORD_KDF)
                        .long(CLAP_ARG_LONG_PASSWORD_KDF)
                        .possible_values(&CLAP_ARG_POSSIBLE_VALUES_PASSWORD_KDF)
                        .requires(CLAP_ARG_NAME_ENCRYPTION_PASSWORD)
                        .takes_value(true))
                    .arg(Arg::with_name(CLAP_ARG_NAME_ENCRYPTION_ALGORITHM)
                        .help(CLAP_ARG_HELP_ENCRYPTION_ALGORITHM)
                        .short(CLAP_ARG_SHORT_ENCRYPTION_ALGORITHM)
                        .long(CLAP_ARG_LONG_ENCRYPTION_ALGORITHM)
                        .possible_values(&CLAP_ARG_POSSIBLE_VALUES_ENCRYPTION_ALGORITHM)
                        .requires(CLAP_ARG_NAME_ENCRYPTION_PASSWORD)
                        .takes_value(true))
                    .arg(Arg::with_name(CLAP_ARG_NAME_ENCRYPTED_HEADER)
                        .help(CLAP_ARG_HELP_ENCRYPTED_HEADER)
                        .short(CLAP_ARG_SHORT_ENCRYPTED_HEADER)
                        .long(CLAP_ARG_LONG_ENCRYPTED_HEADER)
                        .requires(CLAP_ARG_NAME_ENCRYPTION_PASSWORD))
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
    let unique_identifier: u64 = OsRng.next_u64();
    let split_number = 1;
    let length_of_split = 0;
    SplitHeader::new(header_version, unique_identifier, split_number, length_of_split)
}

fn encryption_header(arguments: &ArgMatches) -> Option<(EncryptionHeader, Vec<u8>)> {
    if let Some(password) = arguments.value_of(CLAP_ARG_NAME_ENCRYPTION_PASSWORD) {
        let (kdf, pbes) = match arguments.value_of(CLAP_ARG_NAME_PASSWORD_KDF) {
            None => (KDFScheme::PBKDF2SHA256, PBEScheme::AES256CBC),
            Some(value) => {
                match value {
                    "pbkdf2_sha256_aes128cbc" => (KDFScheme::PBKDF2SHA256, PBEScheme::AES128CBC),
                    "pbkdf2_sha256_aes256cbc" => (KDFScheme::PBKDF2SHA256, PBEScheme::AES256CBC),
                    _ => {
                        println!("{}", ERROR_UNKNOWN_PASSWORD_KDF);
                        exit(EXIT_STATUS_ERROR)
                    }
                }
            }
        };
        let encryption_algorithm = match arguments.value_of(CLAP_ARG_NAME_ENCRYPTION_ALGORITHM) {
            None => EncryptionAlgorithm::AES256GCMSIV,
            Some(value) => match value {
                "aes128-gcm-siv" => EncryptionAlgorithm::AES128GCMSIV,
                "aes256-gcm-siv" => EncryptionAlgorithm::AES256GCMSIV,
                _ => {
                    println!("{}", ERROR_UNKNOWN_ENCRYPTION_ALGORITHM);
                    exit(EXIT_STATUS_ERROR)
                }
            },
        };
        let encryption_key = match encryption_algorithm {
            EncryptionAlgorithm::AES128GCMSIV => Encryption::gen_random_key(128),
            EncryptionAlgorithm::AES256GCMSIV => Encryption::gen_random_key(256),
            _ => {
                println!("{}", ERROR_UNKNOWN_ENCRYPTION_ALGORITHM);
                exit(EXIT_STATUS_ERROR)
            },
        };
        let (pbe_header, encrypted_encryption_key) = match kdf {
            KDFScheme::PBKDF2SHA256 => {
                let pbe_nonce = Encryption::gen_random_iv();
                let iterations = u16::MAX;
                let salt = Encryption::gen_random_salt();
                let kdf_parameters = KDFParameters::PBKDF2SHA256Parameters(PBKDF2SHA256Parameters::new(iterations, salt));
                let pbe_header = PBEHeader::new(PBE_HEADER_VERSION, kdf, pbes.clone(), kdf_parameters, pbe_nonce);
                let encrypted_encryption_key = match pbes {
                    PBEScheme::AES128CBC => match Encryption::encrypt_pbkdf2sha256_aes128cbc(
                        iterations,
                        &salt,
                        &pbe_nonce,
                        password.trim(),
                        &encryption_key,
                        ) {
                        Ok(val) => val,
                        Err(_) => {
                            println!("{}", ERROR_ENCRYPT_KEY);
                            exit(EXIT_STATUS_ERROR);
                        },
                    },
                    PBEScheme::AES256CBC => match Encryption::encrypt_pbkdf2sha256_aes256cbc(
                        iterations,
                        &salt,
                        &pbe_nonce,
                        password.trim(),
                        &encryption_key,
                        ) {
                        Ok(val) => val,
                        Err(_) => {
                            println!("{}", ERROR_ENCRYPT_KEY);
                            exit(EXIT_STATUS_ERROR);
                        }
                    },
                    _ => {
                        println!("{}", ERROR_UNKNOWN_PASSWORD_KDF);
                        exit(EXIT_STATUS_ERROR)
                    },
                };
                (pbe_header, encrypted_encryption_key)
            },
            _ => {
                println!("{}", ERROR_UNKNOWN_PASSWORD_KDF);
                exit(EXIT_STATUS_ERROR)
            },
        };
        let encryption_header = EncryptionHeader::new(
            ENCRYPTION_HEADER_VERSION,
            pbe_header,
            encryption_algorithm,
            encrypted_encryption_key,
            Encryption::gen_random_header_nonce()
            );
        return Some((encryption_header, encryption_key));
    } else {
        return None;
    }
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

fn calculate_chunk_size(arguments: &ArgMatches) -> u8 {
    if let Some(value) = arguments.value_of(CLAP_ARG_NAME_CHUNK_SIZE) {
        // Calling .unwrap() is safe here because the possible values are limited
        let value: f64 = value.parse().unwrap();
        value.log2() as u8
    } else {
        DEFAULT_CHUNK_SIZE as u8
    }
}

fn write_to_output<O>(
    input_path: &PathBuf,
    output_filename: O,
    mut main_header: MainHeader,
    compression_header: CompressionHeader,
    mut split_header: SplitHeader,
    encryption_key: Option<Vec<u8>>,
    encryption_header: Option<EncryptionHeader>)
where
    O: Into<String>,
{
    let mut input_file = match File::open(input_path) {
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

    let header_size = main_header.get_encoded_size();

    let chunk_size = main_header.chunk_size();
    let mut chunk_header = ChunkHeader::new(CHUNK_HEADER_VERSION, DEFAULT_CHUNK_STARTVALUE, 0);

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

    let encoded_main_header = match &encryption_key {
        None => main_header.encode_directly(),
        Some(key) => match main_header.encode_encrypted_header_directly(key) {
            Ok(data) => data,
            Err(e) => {
                println!("{}{}", ERROR_WRITE_ENCRYPTED_MAIN_HEADER, e.to_string());
                exit(EXIT_STATUS_ERROR);
            }
        },
    };

    match output_file.write(&encoded_main_header) {
        Ok(_) => (),
        Err(e) => {
            println!("{}{}", ERROR_WRITE_MAIN_HEADER, e.to_string());
            exit(EXIT_STATUS_ERROR);
        }
    };

    let encryption = match encryption_key {
        None => None,
        Some(ref key) => match encryption_header {
            None => None,
            Some(header) => Some((key, header.encryption_algorithm().clone()))
        },
    };
    
    let mut written_bytes = match write_segment(
        &mut input_file,
        &mut output_file,
        chunk_size,
        &mut chunk_header,
        compression_header.compression_algorithm(),
        compression_header.compression_level(),
        first_segment_size as usize,
        &encryption) {
        Ok(val) => val,
        Err(e) => {
            println!("{}{}", ERROR_COPY_FILESTREAM_TO_OUTPUT, e.to_string());
            exit(EXIT_STATUS_ERROR);
        },
    };

    split_header.set_length_of_split(written_bytes);
    main_header.set_split_header(split_header.clone());

    loop {
        let mut segment_split_header = split_header.next_header();
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

        let written_bytes_in_segment = match write_segment(
            &mut input_file,
            &mut output_file,
            chunk_size,
            &mut chunk_header,
            compression_header.compression_algorithm(),
            compression_header.compression_level(),
            split_size as usize,
            &encryption) {
            Ok(val) => val,
            Err(e) => {
                println!("{}{}", ERROR_COPY_FILESTREAM_TO_OUTPUT, e.to_string());
                exit(EXIT_STATUS_ERROR);
            },
        };
        if written_bytes_in_segment == 0 {
            let _ = remove_file(segment_filename);
            break;
        } else {
            written_bytes += written_bytes_in_segment;
            //rewrite segment header with the correct number of bytes.
            segment_split_header.set_length_of_split(written_bytes_in_segment);
            match output_file.seek(SeekFrom::Start(0)) {
                Ok(_) => (),
                Err(e) => {
                    println!("{}{}", ERROR_REWRITE_SEGMENT_HEADER, e.to_string());
                    exit(EXIT_STATUS_ERROR);
                }
            };
            match output_file.write(&segment_split_header.encode_directly()) {
                Ok(_) => (),
                Err(e) => {
                    println!("{}{}", ERROR_REWRITE_SEGMENT_HEADER, e.to_string());
                    exit(EXIT_STATUS_ERROR);
                }
            };
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
    let encoded_main_header = match &encryption_key {
        None => main_header.encode_directly(),
        Some(key) => match main_header.encode_encrypted_header_directly(key) {
            Ok(data) => if data.len() == encoded_main_header.len() {
                data
            } else {
                println!("{}", ERROR_REWRITE_MAIN_HEADER);
                exit(EXIT_STATUS_ERROR);
            },
            Err(e) => {
                println!("{}{}", ERROR_WRITE_ENCRYPTED_MAIN_HEADER, e.to_string());
                exit(EXIT_STATUS_ERROR);
            }
        },
    };
    match output_file.write(&encoded_main_header) {
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
    let chunk_size = calculate_chunk_size(&arguments);
    let split_header = split_header();

    // Calling .unwrap() is safe here because the arguments are *required*.
    let input_path = PathBuf::from(arguments.value_of(CLAP_ARG_NAME_INPUT_FILE).unwrap());
    let output_filename = arguments.value_of(CLAP_ARG_NAME_OUTPUT_FILE).unwrap();
    let (encryption_header, encryption_key) = match encryption_header(&arguments) {
        None => (None, None),
        Some((header, key)) => (Some(header), Some(key))
    };

    let main_header = MainHeader::new(
        MAIN_HEADER_VERSION,
        encryption_header.clone(),
        compression_header.clone(),
        description_header,
        chunk_size,
        split_size,
        split_header.clone(),
        0);

    write_to_output(&input_path, output_filename, main_header, compression_header, split_header, encryption_key, encryption_header);
}