// - STD
use std::fs::File;
use std::path::PathBuf;
use std::process::exit;

// - modules
mod lib;

// - internal
use lib::constants::*;
use zff::{
    header::*,
    HeaderDecoder,
    ZffErrorKind,
};

// - external
use clap::{Arg, App, ArgMatches};
use toml;
use serde_json;

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
                    .get_matches();
    matches
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

    match MainHeader::decode_directly(&mut input_file) {
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
            ZffErrorKind::HeaderDecodeEncryptedMainHeader => {
                println!("{}", e.to_string());
                exit(EXIT_STATUS_ERROR);
            }
            _ => ()
        }
    }

    //if this is a segment
    unimplemented!()

}