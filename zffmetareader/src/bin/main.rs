// - STD
use std::fs::{File,read_dir};
use std::path::{PathBuf, Path};
use std::process::exit;
use std::io::{self, Seek,Read, BufRead};
use std::{thread};

// - modules
mod lib;

// - internal
use lib::constants::*;
use zff::{
    Result,
    header::*,
    HeaderCoding,
    ZffReader,
    ZffError,
    ZffErrorKind,
    Hash,
    ED25519_DALEK_PUBKEY_LEN,
};

// - external
use clap::{Arg, App, ArgMatches};
use toml;
use serde_json;
use base64;

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
                    .arg(Arg::with_name(CLAP_ARG_NAME_VERIFY)
                        .help(CLAP_ARG_HELP_VERIFY)
                        .short(CLAP_ARG_SHORT_VERIFY)
                        .long(CLAP_ARG_LONG_VERIFY)
                        .requires(CLAP_ARG_NAME_PUBKEYFILE))
                    .arg(Arg::with_name(CLAP_ARG_NAME_PUBKEYFILE)
                        .help(CLAP_ARG_HELP_PUBKEYFILE)
                        .short(CLAP_ARG_SHORT_PUBKEYFILE)
                        .long(CLAP_ARG_LONG_PUBKEYFILE)
                        .takes_value(true))
                    .arg(Arg::with_name(CLAP_ARG_NAME_INTEGRITY_CHECK)
                        .help(CLAP_ARG_HELP_INTEGRITY_CHECK)
                        .short(CLAP_ARG_SHORT_INTEGRITY_CHECK)
                        .long(CLAP_ARG_LONG_INTEGRITY_CHECK))
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

fn create_zff_reader<R: Read + Seek, P: AsRef<[u8]>>(mut data: Vec<R>, password: Option<P>) -> Result<ZffReader<R>> {
    if let Some(password) = password {
        let main_header = match MainHeader::decode_directly(&mut data[0]) {
            Ok(header) => header,
            Err(e) => match e.get_kind() {
                ZffErrorKind::HeaderDecodeMismatchIdentifier => {
                    data[0].rewind()?;
                    MainHeader::decode_encrypted_header_with_password(&mut data[0], &password)?
                },
                _ => return Err(e),
            },
        };
        let mut zff_reader = ZffReader::new(data, main_header)?;
        zff_reader.decrypt_encryption_key(password)?;
        return Ok(zff_reader);
    } else {
        let main_header = MainHeader::decode_directly(&mut data[0])?;
        if let Some(_) = main_header.encryption_header() {
            return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, ERROR_MISSING_ENCRYPTION_KEY));
        };
        let zff_reader = ZffReader::new(data, main_header)?;
        Ok(zff_reader)
    }
}

fn get_input_files(arguments: &ArgMatches) -> Vec<File> {
    // Calling .unwrap() is safe here because the arguments are *required*.
    let mut input_file_paths = Vec::new();
    let input_filename = PathBuf::from(arguments.value_of(CLAP_ARG_NAME_INPUT_FILE).unwrap());
    let input_path = match PathBuf::from(&input_filename).parent() {
        Some(p) => {
            if p.to_string_lossy() == "" {
                match read_dir(PWD) {
                    Ok(iter) => iter,
                    Err(e) => {
                        println!("{}{}", ERROR_UNREADABLE_INPUT_DIR, e.to_string());
                        exit(EXIT_STATUS_ERROR);
                    }
                }
            } else {
                match read_dir(p) {
                    Ok(iter) => iter,
                    Err(e) => {
                        println!("{}{}", ERROR_UNREADABLE_INPUT_DIR, e.to_string());
                        exit(EXIT_STATUS_ERROR);
                    }
                }
            }
        }
        None => {
            println!("{}", ERROR_UNDETERMINABLE_INPUT_DIR);
            exit(EXIT_STATUS_ERROR);
        }
    };
    for filename in input_path {
        match filename {
            Ok(n) if n.path().is_file() => {
                if n.path().file_stem() == input_filename.file_stem() {
                    input_file_paths.push(n.path());
                }
            }
            _ => ()
        }
    }

    input_file_paths.sort();
    let mut input_files = Vec::new();
    for path in input_file_paths {
        let segment_file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => {
                println!("{}{}", ERROR_OPEN_INPUT_FILE, path.to_string_lossy());
                exit(EXIT_STATUS_ERROR);
            }
        };
        input_files.push(segment_file);
    }

    input_files
}

fn get_zff_reader(arguments: &ArgMatches, header_signature: &HeaderSignature, input_files: Vec<File>) -> ZffReader<File>{
    let zff_reader = match header_signature {
        HeaderSignature::EncryptedMainHeader => {
            let password = match arguments.value_of(CLAP_ARG_NAME_PASSWORD) {
                Some(pw) => pw,
                None => {
                    println!("{}", ERROR_NO_PASSWORD);
                    exit(EXIT_STATUS_ERROR);
                }
            };

            let mut zff_reader = match create_zff_reader(input_files, Some(password)) {
                Ok(reader) => reader,
                Err(e) => {
                    println!("{}{}", ERROR_START_ANALYSIS, e.to_string());
                    exit(EXIT_STATUS_ERROR);
                },
            };

            match zff_reader.decrypt_encryption_key(password.trim()) {
                Ok(_) => (),
                Err(_) => {
                    println!("{}{}", ERROR_PARSE_ENCRYPTED_MAIN_HEADER, ERROR_WRONG_PASSWORD);
                    exit(EXIT_STATUS_ERROR);
                }
            };

            zff_reader
        },
        _ => {
            match create_zff_reader(input_files, None::<String>) {
                Ok(reader) => reader,
                Err(e) => {
                    println!("{}{}", ERROR_START_ANALYSIS, e.to_string());
                    exit(EXIT_STATUS_ERROR);
                },
            }
        },
    };
    zff_reader
}

fn check_integrity(arguments: &ArgMatches, header_signature: &HeaderSignature) {
    let input_files = get_input_files(arguments);
    let zff_reader = get_zff_reader(arguments, header_signature, input_files);

    let hash_values = zff_reader.main_header().hash_header().hash_values();
    let mut handles = Vec::new();
    for value in hash_values {
        let value = value.clone();
        let input_files = get_input_files(arguments);
        let zff_reader = get_zff_reader(arguments, header_signature, input_files);
        handles.push(thread::spawn(move || {
            check_integrity_for_hash_value(value, zff_reader);
        }));
    }
    for handle in handles {
        match handle.join() {
            Ok(_) => (),
            Err(_) => {
                println!("{}", HASHING_THREAD_PANIC);
                exit(EXIT_STATUS_ERROR);
            }
        };
    }
    exit(EXIT_STATUS_SUCCESS);
}

fn check_integrity_for_hash_value(value: HashValue, mut zff_reader: ZffReader<File>) {
    let chunk_size = zff_reader.main_header().chunk_size();
    let mut hasher = Hash::new_hasher(value.hash_type());
    let mut buffer = vec![0u8; chunk_size];
        loop {
            let count = match zff_reader.read(&mut buffer){
                Ok(x) => x,
                Err(e) => {
                    println!("{}{}", ERROR_HASHING_DATA, e.to_string());
                    exit(EXIT_STATUS_ERROR);
                },
            };
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let hash = hasher.finalize();
    if value.hash() == &hash.to_vec() {
        println!("{}{}", value.hash_type().to_string(), CORRECT_HASH)
    } else {
        println!("{}{}", value.hash_type().to_string(), INCORRECT_HASH)
    }
}

fn verify_image(arguments: &ArgMatches, header_signature: &HeaderSignature) {
    let input_files = get_input_files(arguments);

    let mut public_key = [0; ED25519_DALEK_PUBKEY_LEN];
    // Calling .unwrap() is safe here because the arguments are *required*.
    let path = &arguments.value_of(CLAP_ARG_NAME_PUBKEYFILE).unwrap();
    let mut file_content = match read_lines(&path) {
        Ok(content) => content,
        Err(_) => {
            println!("{}{}", ERROR_OPEN_FILE_PUBKEY, &path);
            exit(EXIT_STATUS_ERROR);
        }
    };
    let base64_encoded_pubkey = match file_content.next() {
        Some(Ok(line)) => line,
        _ => {
            println!("{}{}", ERROR_DECODE_BASE64_PUBKEY, ERROR_EMPTY_FILE);
            exit(EXIT_STATUS_ERROR);
        }
    };
    let decoded_key = match base64::decode(base64_encoded_pubkey.trim()) {
        Ok(key) => key,
        Err(e) => {
            println!("{}{}", ERROR_DECODE_BASE64_PUBKEY, e.to_string());
            exit(EXIT_STATUS_ERROR);
        }
    };
    match decoded_key.as_slice().read_exact(&mut public_key) {
        Ok(_) => (),
        Err(e) => {
            println!("{}{}", ERROR_READ_PUBKEY, e.to_string());
            exit(EXIT_STATUS_ERROR);
        }
    };    

    let mut zff_reader = get_zff_reader(arguments, header_signature, input_files);

    match zff_reader.verify_all(public_key, false) {
        Ok(vec) => {
            if vec.len() == 0 {
                println!("{}", VERIFIER_RESULT_SUCCESS);
                exit(EXIT_STATUS_SUCCESS);
            } else {
                println!("{}", VERIFIER_RESULT_CORRUPTION_FOUND);
                for chunk_no in vec {
                    println!("{}", chunk_no);
                }
                exit(EXIT_STATUS_SUCCESS);
            }
        },
        Err(e) => {
            println!("{}{}", VERIFIER_RESULT_ERROR, e.to_string());
            exit(EXIT_STATUS_ERROR);
        }
    }
}

// The output is wrapped in a Result to allow matching on errors
// Returns an Iterator to the Reader of the lines of the file.
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
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

    let header_signature = if u32::from_be_bytes(header_signature) == MainHeader::identifier() {
        HeaderSignature::MainHeader
    } else if u32::from_be_bytes(header_signature) == SegmentHeader::identifier() {
        HeaderSignature::SegmentHeader
    } else if u32::from_be_bytes(header_signature) == MainHeader::encrypted_header_identifier() {
        HeaderSignature::EncryptedMainHeader
    } else {
        println!("{}", ERROR_UNKNOWN_HEADER);
        exit(EXIT_STATUS_ERROR);
    };

    if arguments.is_present(CLAP_ARG_NAME_VERIFY) {
        verify_image(&arguments, &header_signature)
    }
    if arguments.is_present(CLAP_ARG_NAME_INTEGRITY_CHECK) {
        check_integrity(&arguments, &header_signature)
    }

    match header_signature {
        HeaderSignature::MainHeader => decode_main_header_unencrypted(&mut input_file, &arguments),
        HeaderSignature::SegmentHeader => decode_segment_header(&mut input_file, &arguments),
        HeaderSignature::EncryptedMainHeader => decode_main_header_encrypted(&mut input_file, &arguments)
    }

       
}

enum HeaderSignature {
    MainHeader,
    SegmentHeader,
    EncryptedMainHeader,
}