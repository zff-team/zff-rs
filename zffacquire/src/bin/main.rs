// - STD
use std::{
    time::{SystemTime,UNIX_EPOCH},
    path::{PathBuf},
    fs::{File, remove_file},
    process::exit,
    io::{Write, Seek, SeekFrom},
    collections::HashMap,
};

// - extern crates
extern crate clap;
extern crate rand;
extern crate zff;

// - modules
mod lib;

// - internal
use crate::lib::*;
use zff::{
    header::*,
    EncryptionAlgorithm,
    CompressionAlgorithm,
    HashType,
    Hash,
    HeaderEncoder,
    KDFScheme,
    PBEScheme,
    write_segment,
    file_extension_next_value,
    Encryption,
    Signature,
    FILE_EXTENSION_FIRST_VALUE,
    DEFAULT_CHUNK_SIZE,
};

// - external
use clap::{
    Arg,
    App,
    ArgMatches
};
use rand::{Rng};
use ed25519_dalek::Keypair;

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
                    .arg(Arg::with_name(CLAP_ARG_NAME_SEGMENT_SIZE)
                        .help(CLAP_ARG_HELP_SEGMENT_SIZE)
                        .short(CLAP_ARG_SHORT_SEGMENT_SIZE)
                        .long(CLAP_ARG_LONG_SEGMENT_SIZE)
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
                    .arg(Arg::with_name(CLAP_ARG_NAME_HASH_ALGORITHM)
                        .help(CLAP_ARG_HELP_HASH_ALGORITHM)
                        .short(CLAP_ARG_SHORT_HASH_ALGORITHM)
                        .long(CLAP_ARG_LONG_HASH_ALGORITHM)
                        .possible_values(&CLAP_ARG_POSSIBLE_VALUES_HASH_ALGORITHM)
                        .multiple(true)
                        .takes_value(true))
                    .arg(Arg::with_name(CLAP_ARG_NAME_SIGN_DATA)
                        .help(CLAP_ARG_HELP_SIGN_DATA)
                        .short(CLAP_ARG_SHORT_SIGN_DATA)
                        .long(CLAP_ARG_LONG_SIGN_DATA)
                        .takes_value(false))
                    .arg(Arg::with_name(CLAP_ARG_NAME_SIGN_KEYPAIR)
                        .help(CLAP_ARG_HELP_SIGN_KEYPAIR)
                        .short(CLAP_ARG_SHORT_SIGN_KEYPAIR)
                        .long(CLAP_ARG_LONG_SIGN_KEYPAIR)
                        .requires(CLAP_ARG_NAME_SIGN_DATA)
                        .takes_value(true))
                    .get_matches();
    matches
}

fn signer(arguments: &ArgMatches) -> Option<Keypair> {
    if !arguments.is_present(CLAP_ARG_NAME_SIGN_DATA) {
        return None;
    }
    match arguments.value_of(CLAP_ARG_NAME_SIGN_KEYPAIR) {
        None => Some(Signature::new_keypair()),
        Some(value) => match Signature::new_keypair_from_base64(value.trim()) {
            Ok(keypair) => return Some(keypair),
            Err(_) => {
                println!("{}", ERROR_PARSE_KEY);
                exit(EXIT_STATUS_ERROR);
            },
        }
    }
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
        Ok(now) => description_header.set_acquisition_start(now.as_secs()),
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

fn segment_header() -> SegmentHeader {
    let mut rng = rand::thread_rng();
    let header_version = SEGMENT_HEADER_VERSION;
    let unique_identifier: i64 = rng.gen();
    let segment_number = 1;
    let length_of_segment = 0;
    SegmentHeader::new(header_version, unique_identifier, segment_number, length_of_segment)
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

fn calculate_segment_size(arguments: &ArgMatches) -> u64 {
    //TODO: support human readable segment size entries, like 4G or 200M.
    if let Some(value) = arguments.value_of(CLAP_ARG_NAME_SEGMENT_SIZE) {
        match value.parse() {
            Ok(val) => val,
            Err(_) => {
                println!("{}{}", ERROR_PARSE_STR_SEGMENT_SIZE, value);
                exit(EXIT_STATUS_ERROR);
            }
        }
    } else {
        u64::MAX
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


fn get_hashes(arguments: &ArgMatches) -> Vec<HashValue> {
    let mut hashvalues = Vec::new();
    let values: Vec<_> = match arguments.values_of(CLAP_ARG_NAME_HASH_ALGORITHM) {
        None => {
            hashvalues.push(HashValue::new_empty(HASH_VALUE_HEADER_VERSION, Hash::default_hashtype()));
            return hashvalues;
        },
        Some(values) => values.collect(),
    };
    for value in values {
        match value {
            "blake2b-512" => hashvalues.push(HashValue::new_empty(HASH_VALUE_HEADER_VERSION, HashType::Blake2b512)),
            "sha256" => hashvalues.push(HashValue::new_empty(HASH_VALUE_HEADER_VERSION, HashType::SHA256)),
            "sha512" => hashvalues.push(HashValue::new_empty(HASH_VALUE_HEADER_VERSION, HashType::SHA512)),
            "sha3-256" => hashvalues.push(HashValue::new_empty(HASH_VALUE_HEADER_VERSION, HashType::SHA3_256)),
            _ => {
                println!("{}{}", ERROR_GET_HASHTYPES, value);
                exit(EXIT_STATUS_ERROR)
            }
        }
    }
    hashvalues
}

fn write_to_output<O>(
    input_path: &PathBuf,
    output_filename: O,
    mut main_header: MainHeader,
    compression_header: CompressionHeader,
    mut segment_header: SegmentHeader,
    encryption_key: Option<Vec<u8>>,
    encryption_header: Option<EncryptionHeader>,
    hash_values: Vec<HashValue>,
    signature_key: Option<Keypair>)
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
    let segment_size = main_header.segment_size();

    let header_size = main_header.get_encoded_size();

    let chunk_size = main_header.chunk_size();
    let mut chunk_header = ChunkHeader::new(CHUNK_HEADER_VERSION, DEFAULT_CHUNK_STARTVALUE, 0, 0, None);

    if (segment_size as usize) < header_size {
        println!("{}", ERROR_SEGMENT_SIZE_TOO_SMALL_FOR_MAINHEADER);
        exit(EXIT_STATUS_ERROR);
    }
    let first_segment_size = segment_size as usize - header_size;
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
            Some(header) => Some((key, header.algorithm().clone()))
        },
    };

    let mut hasher_map = HashMap::new();
    for value in hash_values {
        let hasher = Hash::new_hasher(value.hash_type());
        hasher_map.insert(value.hash_type().clone(), hasher);
    };
    
    let mut written_bytes = match write_segment(
        &mut input_file,
        &mut output_file,
        chunk_size,
        &mut chunk_header,
        compression_header.algorithm(),
        compression_header.level(),
        first_segment_size as usize,
        &encryption,
        &mut hasher_map,
        &signature_key) {
        Ok(val) => val,
        Err(e) => {
            println!("{}{}", ERROR_COPY_FILESTREAM_TO_OUTPUT, e.to_string());
            exit(EXIT_STATUS_ERROR);
        },
    };

    segment_header.set_length_of_segment(written_bytes);
    main_header.set_segment_header(segment_header.clone());

    loop {
        let mut segment_header = segment_header.next_header();
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

        match output_file.write(&segment_header.encode_directly()) {
            Ok(_) => (),
            Err(_) => {
                println!("{}{}", ERROR_WRITE_SEGMENT_HEADER, segment_filename.to_string_lossy());
                exit(EXIT_STATUS_ERROR);
            }
        };

        let written_bytes_in_segment = match write_segment(
            &mut input_file,
            &mut output_file,
            chunk_size,
            &mut chunk_header,
            compression_header.algorithm(),
            compression_header.level(),
            segment_size as usize,
            &encryption,
            &mut hasher_map,
            &signature_key) {
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
            segment_header.set_length_of_segment(written_bytes_in_segment);
            match output_file.seek(SeekFrom::Start(0)) {
                Ok(_) => (),
                Err(e) => {
                    println!("{}{}", ERROR_REWRITE_SEGMENT_HEADER, e.to_string());
                    exit(EXIT_STATUS_ERROR);
                }
            };
            match output_file.write(&segment_header.encode_directly()) {
                Ok(_) => (),
                Err(e) => {
                    println!("{}{}", ERROR_REWRITE_SEGMENT_HEADER, e.to_string());
                    exit(EXIT_STATUS_ERROR);
                }
            };
        }
    }

    let mut hash_values = Vec::new();
    for (hash_type, hasher) in hasher_map {
        let hash = hasher.finalize();
        let mut hash_value = HashValue::new_empty(HASH_VALUE_HEADER_VERSION, hash_type);
        hash_value.set_hash(hash.to_vec());
        hash_values.push(hash_value);
    }
    let hash_header = HashHeader::new(HASH_HEADER_VERSION, hash_values);

    //rewrite main_header with the correct number of bytes of the COMPRESSED data.
    main_header.set_length_of_data(written_bytes);
    main_header.set_hash_header(hash_header);
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => main_header.set_acquisition_end(now.as_secs()),
        Err(_) => ()
    };
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
    let segment_size = calculate_segment_size(&arguments);
    let chunk_size = calculate_chunk_size(&arguments);
    let segment_header = segment_header();

    // Calling .unwrap() is safe here because the arguments are *required*.
    let input_path = PathBuf::from(arguments.value_of(CLAP_ARG_NAME_INPUT_FILE).unwrap());
    let output_filename = arguments.value_of(CLAP_ARG_NAME_OUTPUT_FILE).unwrap();
    let (encryption_header, encryption_key) = match encryption_header(&arguments) {
        None => (None, None),
        Some((header, key)) => (Some(header), Some(key))
    };

    let hash_values = get_hashes(&arguments);
    let hash_header = HashHeader::new(HASH_HEADER_VERSION, hash_values.clone());
    let signature_key = signer(&arguments);
    let signature_flag = match signature_key {
        None => 0,
        Some(_) => 1,
    };

    let main_header = MainHeader::new(
        MAIN_HEADER_VERSION,
        encryption_header.clone(),
        compression_header.clone(),
        description_header,
        hash_header,
        chunk_size,
        signature_flag,
        segment_size,
        0,
        segment_header.clone());

    write_to_output(
        &input_path,
        output_filename,
        main_header,
        compression_header,
        segment_header,
        encryption_key,
        encryption_header,
        hash_values,
        signature_key);
}