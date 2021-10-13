// - STD
use std::fs::File;
use std::path::PathBuf;
use std::process::exit;
use std::io::{Seek,Read};

// - modules
mod lib;

// - internal
use lib::constants::*;
use zff::{
    header::*,
    HeaderCoding,
    ZffErrorKind,
};

// - external
use clap::{Arg, App, ArgMatches};
use toml;
use serde_json;

// parsing incoming arguments.
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
                    .arg(Arg::with_name(CLAP_ARG_NAME_OUTPUT_FORMAT)
                        .help(CLAP_ARG_HELP_OUTPUT_FORMAT)
                        .short(CLAP_ARG_SHORT_OUTPUT_FORMAT)
                        .long(CLAP_ARG_LONG_OUTPUT_FORMAT)
                        .possible_values(&CLAP_ARG_POSSIBLE_VALUES_OUTPUT_FORMAT)
                        .default_value(CLAP_ARG_DEFAULT_VALUE_OUTPUT_FORMAT)
                        .takes_value(true))
                    .arg(Arg::with_name(CLAP_ARG_NAME_PASSWORD)
                        .help(CLAP_ARG_HELP_PASSWORD)
                        .short(CLAP_ARG_SHORT_PASSWORD)
                        .long(CLAP_ARG_LONG_PASSWORD)
                        .takes_value(true))
                    .get_matches();
    matches
}

fn decode_main_header_unencrypted<R: Read>(input_file: &mut R, arguments: &ArgMatches) {
    match MainHeader::decode_directly(input_file) {
        // is_ok() if this file contains an unencrypted (well formatted) main header.
        Ok(header) => {
            // Calling .unwrap() is safe here because this argument has a default value.
            match arguments.value_of(CLAP_ARG_NAME_OUTPUT_FORMAT).unwrap() {
                CLAP_ARG_VALUE_OUTPUT_FORMAT_TOML => match toml::Value::try_from(&header) {
                    Ok(value) => {
                        println!("{}", value);
                        exit(EXIT_STATUS_SUCCESS);
                    },
                    Err(_) => {
                        println!("{}", ERROR_SERIALIZE_TOML);
                        exit(EXIT_STATUS_ERROR);
                    }
                },
                CLAP_ARG_VALUE_OUTPUT_FORMAT_JSON => match serde_json::to_string(&header) {
                    Ok(value) => {
                        println!("{}", value);
                        exit(EXIT_STATUS_SUCCESS);
                    },
                    Err(_) => {
                        println!("{}", ERROR_SERIALIZE_JSON);
                        exit(EXIT_STATUS_ERROR);
                    }
                },
                CLAP_ARG_VALUE_OUTPUT_FORMAT_JSON_PRETTY => match serde_json::to_string_pretty(&header) {
                    Ok(value) => {
                        println!("{}", value);
                        exit(EXIT_STATUS_SUCCESS);
                    },
                    Err(_) => {
                        println!("{}", ERROR_SERIALIZE_JSON);
                        exit(EXIT_STATUS_ERROR);
                    }
                }
                _ => {
                    println!("{}", ERROR_SERIALIZE_UNKNOWN_SERIALIZER);
                    exit(EXIT_STATUS_ERROR);
                }
            }
        },
        Err(e) => {
            println!("{}{}", ERROR_PARSE_MAIN_HEADER, e.to_string());
            exit(EXIT_STATUS_ERROR);
        },
    }
}

fn decode_segment_header<R: Read>(input_file: &mut R, arguments: &ArgMatches) {
    match SegmentHeader::decode_directly(input_file) {
        // is_ok() if this file contains a segment header (without a main header).
        Ok(header) => {
            // Calling .unwrap() is safe here because this argument has a default value.
            match arguments.value_of(CLAP_ARG_NAME_OUTPUT_FORMAT).unwrap() {
                CLAP_ARG_VALUE_OUTPUT_FORMAT_TOML => match toml::Value::try_from(&header) {
                    Ok(value) => {
                        println!("{}", value);
                        exit(EXIT_STATUS_SUCCESS);
                    },
                    Err(_) => {
                        println!("{}", ERROR_SERIALIZE_TOML);
                        exit(EXIT_STATUS_ERROR);
                    }
                },
                CLAP_ARG_VALUE_OUTPUT_FORMAT_JSON => match serde_json::to_string(&header) {
                    Ok(value) => {
                        println!("{}", value);
                        exit(EXIT_STATUS_SUCCESS);
                    },
                    Err(_) => {
                        println!("{}", ERROR_SERIALIZE_JSON);
                        exit(EXIT_STATUS_ERROR);
                    }
                },
                CLAP_ARG_VALUE_OUTPUT_FORMAT_JSON_PRETTY => match serde_json::to_string_pretty(&header) {
                    Ok(value) => {
                        println!("{}", value);
                        exit(EXIT_STATUS_SUCCESS);
                    },
                    Err(_) => {
                        println!("{}", ERROR_SERIALIZE_JSON);
                        exit(EXIT_STATUS_ERROR);
                    }
                }
                _ => {
                    println!("{}", ERROR_SERIALIZE_UNKNOWN_SERIALIZER);
                    exit(EXIT_STATUS_ERROR);
                }
            }
        },
        Err(e) => {
            println!("{}{}", ERROR_PARSE_SEGMENT_HEADER, e.to_string());
            exit(EXIT_STATUS_ERROR);
        }
    }
}

fn decode_main_header_encrypted<R: Read>(input_file: &mut R, arguments: &ArgMatches) {
    let password = match arguments.value_of(CLAP_ARG_NAME_PASSWORD) {
        Some(pw) => pw,
        None => {
            println!("{}", ERROR_NO_PASSWORD);
            exit(EXIT_STATUS_ERROR);
        }
    };
    match MainHeader::decode_encrypted_header_with_password(input_file, password) {
        // is_ok() if this file contains an encrypted (well formatted) main header and the password is correct.
        Ok(header) => {
            // Calling .unwrap() is safe here because this argument has a default value.
            match arguments.value_of(CLAP_ARG_NAME_OUTPUT_FORMAT).unwrap() {
                CLAP_ARG_VALUE_OUTPUT_FORMAT_TOML => match toml::Value::try_from(&header) {
                    Ok(value) => {
                        println!("{}", value);
                        exit(EXIT_STATUS_SUCCESS);
                    },
                    Err(_) => {
                        println!("{}", ERROR_SERIALIZE_TOML);
                        exit(EXIT_STATUS_ERROR);
                    }
                },
                CLAP_ARG_VALUE_OUTPUT_FORMAT_JSON => match serde_json::to_string(&header) {
                    Ok(value) => {
                        println!("{}", value);
                        exit(EXIT_STATUS_SUCCESS);
                    },
                    Err(_) => {
                        println!("{}", ERROR_SERIALIZE_JSON);
                        exit(EXIT_STATUS_ERROR);
                    }
                },
                CLAP_ARG_VALUE_OUTPUT_FORMAT_JSON_PRETTY => match serde_json::to_string_pretty(&header) {
                    Ok(value) => {
                        println!("{}", value);
                        exit(EXIT_STATUS_SUCCESS);
                    },
                    Err(_) => {
                        println!("{}", ERROR_SERIALIZE_JSON);
                        exit(EXIT_STATUS_ERROR);
                    }
                }
                _ => {
                    println!("{}", ERROR_SERIALIZE_UNKNOWN_SERIALIZER);
                    exit(EXIT_STATUS_ERROR);
                }
            }
        },
        Err(e) => match e.get_kind() {
            ZffErrorKind::PKCS5CryptoError => {
                println!("{}{}", ERROR_PARSE_ENCRYPTED_MAIN_HEADER, ERROR_WRONG_PASSWORD);
                exit(EXIT_STATUS_ERROR);
            },
            _ => {
                println!("{}{}", ERROR_PARSE_ENCRYPTED_MAIN_HEADER, e.to_string());
                exit(EXIT_STATUS_ERROR);
            }
        }
    }
}

fn main() {
    let arguments = arguments();

    // Calling .unwrap() is safe here because the arguments are *required*.
    let input_path = PathBuf::from(arguments.value_of(CLAP_ARG_NAME_INPUT_FILE).unwrap());
    let mut input_file = match File::open(input_path) {
        Ok(file) => file,
        Err(_) => {
            println!("{}", ERROR_OPEN_INPUT_FILE);
            exit(EXIT_STATUS_ERROR);
        }
    };

    let mut header_signature = [0u8; 4];
    match input_file.read_exact(&mut header_signature) {
        Ok(_) => (),
        Err(e) => {
            println!("{}: {}", ERROR_FILE_READ, e.to_string());
            exit(EXIT_STATUS_ERROR);
        },
    };
    match input_file.rewind() {
        Ok(_) => (),
        Err(e) => {
            println!("{}: {}", ERROR_FILE_READ, e.to_string());
            exit(EXIT_STATUS_ERROR);
        }
    };

    if u32::from_be_bytes(header_signature) == MainHeader::identifier() {
        decode_main_header_unencrypted(&mut input_file, &arguments)
    } else if u32::from_be_bytes(header_signature) == SegmentHeader::identifier() {
        decode_segment_header(&mut input_file, &arguments)
    } else if u32::from_be_bytes(header_signature) == MainHeader::encrypted_header_identifier() {
        decode_main_header_encrypted(&mut input_file, &arguments)
    } else {
        println!("{}", ERROR_UNKNOWN_HEADER);
        exit(EXIT_STATUS_ERROR);
    }    
}