use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::sync::Mutex;

use crate::io::{
    ZffCreationParameters, compress_buffer,
    zffreader::{ObjectType as ReaderObjectType, ZffReader},
    zffwriter::{SegmentationState, ZffFilesOutput, ZffWriter},
};
use crate::prelude::*;
use crate::{
    FileTypeEncodingInformation, HashType, LogicalObjectSource, LogicalObjectSourceFilesystem,
    Signature, VirtualFileContent, decompress_buffer, decrypt_argon2_aes128cbc,
    decrypt_argon2_aes256cbc, decrypt_pbkdf2sha256_aes256cbc, decrypt_scrypt_aes256cbc,
    encrypt_argon2_aes128cbc, encrypt_argon2_aes256cbc, encrypt_pbkdf2sha256_aes256cbc,
    encrypt_scrypt_aes256cbc, gen_random_iv, gen_random_key, gen_random_salt,
};

/// The writer used throughout these tests: an in-memory input source and an
/// in-memory reader for the deduplication metadata.
type TestZffWriter = ZffWriter<Cursor<Vec<u8>>, Mutex<Cursor<Vec<u8>>>>;

fn physical_object_header_with_number(
    object_number: u64,
    chunk_size: u64,
    compression_header: CompressionHeader,
) -> ObjectHeader {
    ObjectHeader::new(
        object_number,
        None,
        chunk_size,
        compression_header,
        DescriptionHeader::new_empty(),
        ObjectType::Physical,
        ObjectFlags::default(),
    )
}

fn physical_object_header(chunk_size: u64, compression_header: CompressionHeader) -> ObjectHeader {
    physical_object_header_with_number(1, chunk_size, compression_header)
}

fn default_creation_parameters() -> ZffCreationParameters<Mutex<Cursor<Vec<u8>>>> {
    ZffCreationParameters {
        signature_key: None,
        target_segment_size: None,
        description_notes: None,
        chunkmap_size: None,
        deduplication_metadata: None,
        unique_identifier: 0x5A_FF,
    }
}

fn encode_physical_container(objects: Vec<(ObjectHeader, Vec<u8>)>) -> Vec<u8> {
    let mut physical_objects = HashMap::new();
    for (object_header, input) in objects {
        physical_objects.insert(object_header, Cursor::new(input));
    }

    let mut writer: TestZffWriter = ZffWriter::new(
        physical_objects,
        HashMap::new(),
        HashMap::new(),
        vec![HashType::Blake3],
        default_creation_parameters(),
        ZffFilesOutput::Stream,
    )
    .unwrap();
    let mut container = Vec::new();
    writer.read_to_end(&mut container).unwrap();
    container
}

fn initialized_reader(container: Vec<u8>) -> ZffReader<Mutex<Cursor<Vec<u8>>>> {
    let mut reader = ZffReader::with_reader(vec![Mutex::new(Cursor::new(container))]).unwrap();
    reader.initialize_objects_all().unwrap();
    reader
}

#[test]
fn zstd_compression_keeps_a_complete_frame() {
    let input = vec![0xAB; 4096];
    let compression_header = CompressionHeader::new(CompressionAlgorithm::Zstd, 3, 1.05);

    let (compressed, was_compressed) = compress_buffer(input.clone(), &compression_header).unwrap();

    assert!(was_compressed);
    assert_ne!(compressed, input);
    assert_eq!(
        decompress_buffer(&compressed, CompressionAlgorithm::Zstd).unwrap(),
        input
    );
}

#[test]
fn zstd_compression_returns_raw_data_when_ratio_is_not_worthwhile() {
    let input = b"threshold should reject this compression result".repeat(128);
    let compression_header = CompressionHeader::new(CompressionAlgorithm::Zstd, 3, 10_000.0);

    let (data, was_compressed) = compress_buffer(input.clone(), &compression_header).unwrap();

    assert!(!was_compressed);
    assert_eq!(data, input);
}

#[test]
fn zstd_compression_rejects_invalid_threshold() {
    let compression_header = CompressionHeader::new(CompressionAlgorithm::Zstd, 3, 0.0);

    let result = compress_buffer(vec![0; 128], &compression_header);

    assert!(result.is_err());
}

#[test]
fn lz4_compression_keeps_a_complete_frame() {
    let input = b"lz4 frame payload ".repeat(512);
    let compression_header = CompressionHeader::new(CompressionAlgorithm::Lz4, 0, 1.01);

    let (compressed, was_compressed) = compress_buffer(input.clone(), &compression_header).unwrap();

    assert!(was_compressed);
    assert_ne!(compressed, input);
    assert_eq!(
        decompress_buffer(&compressed, CompressionAlgorithm::Lz4).unwrap(),
        input
    );
}

#[test]
fn malformed_header_length_returns_error() {
    let compression_header = CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0);
    let mut encoded = compression_header.encode_directly();
    encoded[4..12].copy_from_slice(&4_u64.to_le_bytes());

    let result = CompressionHeader::decode_directly(&mut Cursor::new(encoded));

    assert!(matches!(
        result.unwrap_err().kind_ref(),
        ZffErrorKind::EncodingError
    ));
}

#[test]
fn absurd_vec_length_returns_error_before_allocation() {
    let mut encoded_length = Cursor::new(u64::MAX.to_le_bytes().to_vec());

    let result = Vec::<u8>::decode_directly(&mut encoded_length);

    assert!(result.is_err());
}

#[test]
fn physical_object_roundtrip_without_compression() {
    let input = b"zff roundtrip data across several chunks".repeat(32);
    let object_header = physical_object_header(
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let container = encode_physical_container(vec![(object_header, input.clone())]);

    let mut reader = ZffReader::with_reader(vec![Mutex::new(Cursor::new(container))]).unwrap();
    assert_eq!(
        reader.list_objects().unwrap().get(&1),
        Some(&ReaderObjectType::Physical)
    );

    reader.initialize_object(1).unwrap();
    reader.set_active_object(1).unwrap();

    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();

    assert_eq!(output, input);
}

#[test]
fn physical_object_roundtrip_with_zstd_compression() {
    let input = b"compressed zff roundtrip data ".repeat(256);
    let object_header = physical_object_header(
        128,
        CompressionHeader::new(CompressionAlgorithm::Zstd, 3, 1.01),
    );
    let container = encode_physical_container(vec![(object_header, input.clone())]);
    let mut reader = initialized_reader(container);

    reader.set_active_object(1).unwrap();
    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();

    assert_eq!(output, input);
}

#[test]
fn physical_object_read_at_crosses_chunk_boundaries() {
    let input: Vec<u8> = (0..128).collect();
    let object_header = physical_object_header(
        16,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let container = encode_physical_container(vec![(object_header, input.clone())]);
    let reader = initialized_reader(container);
    let mut output = vec![0; 30];

    let read = reader.read_at(&mut output, 1, 0, 11).unwrap();

    assert_eq!(read, output.len());
    assert_eq!(output, input[11..41]);
}

#[test]
fn multiple_physical_objects_can_be_read_back() {
    let first_input = b"first physical object".repeat(64);
    let second_input = b"second physical object".repeat(64);
    let first_header = physical_object_header_with_number(
        1,
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let second_header = physical_object_header_with_number(
        2,
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let container = encode_physical_container(vec![
        (first_header, first_input.clone()),
        (second_header, second_input.clone()),
    ]);
    let mut reader = initialized_reader(container);

    assert_eq!(reader.list_objects().unwrap().len(), 2);
    let mut outputs = Vec::new();
    for object_number in [1, 2] {
        reader.set_active_object(object_number).unwrap();
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        outputs.push(output);
    }

    assert!(outputs.contains(&first_input));
    assert!(outputs.contains(&second_input));
}

#[test]
fn object_header_roundtrip_preserves_public_fields() {
    let mut description_header = DescriptionHeader::new_empty();
    description_header.set_case_number("case-42");
    description_header.set_examiner_name("tester");
    let object_header = ObjectHeader::new(
        7,
        None,
        4096,
        CompressionHeader::new(CompressionAlgorithm::Lz4, 0, 1.25),
        description_header,
        ObjectType::Physical,
        ObjectFlags {
            encryption: false,
            sign_hash: true,
            passive_object: false,
        },
    );
    let encoded = object_header.encode_directly();

    let decoded = ObjectHeader::decode_directly(&mut Cursor::new(encoded)).unwrap();

    assert_eq!(decoded.object_number, 7);
    assert_eq!(decoded.flags.sign_hash, object_header.flags.sign_hash);
    assert_eq!(decoded.chunk_size, object_header.chunk_size);
    assert_eq!(decoded.compression_header, object_header.compression_header);
    assert_eq!(decoded.description_header, object_header.description_header);
    assert_eq!(decoded.object_type, object_header.object_type);
}

#[test]
fn tiny_input_is_rejected_as_container() {
    let input = Mutex::new(Cursor::new(vec![0_u8; 7]));

    let result = ZffReader::with_reader(vec![input]);

    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Encryption
// ---------------------------------------------------------------------------

/// Builds an [EncryptionHeader] whose encryption key is wrapped with the given
/// password, using Argon2id parameters that are cheap enough for a test run.
fn encryption_header_with_password(
    algorithm: EncryptionAlgorithm,
    password: &str,
) -> (EncryptionHeader, Vec<u8>) {
    let key_length = match algorithm {
        EncryptionAlgorithm::AES128GCM => 16,
        EncryptionAlgorithm::AES256GCM | EncryptionAlgorithm::CHACHA20POLY1305 => 32,
    };
    let encryption_key = gen_random_key(key_length * 8);
    let salt = gen_random_salt();
    let nonce = gen_random_iv();
    // Deliberately weak KDF parameters: these tests assert wiring, not KDF cost.
    let argon2_parameters = Argon2idParameters::new(8, 1, 1, salt);
    let encrypted_encryption_key =
        encrypt_argon2_aes256cbc(8, 1, 1, &salt, &nonce, password, &encryption_key).unwrap();
    let pbe_header = PBEHeader::new(
        KDFScheme::Argon2id,
        PBEScheme::AES256CBC,
        KDFParameters::Argon2idParameters(argon2_parameters),
        nonce,
    );
    let encryption_header = EncryptionHeader::new(pbe_header, algorithm, encrypted_encryption_key);
    (encryption_header, encryption_key)
}

#[test]
fn argon2_aes256cbc_roundtrip() {
    let salt = gen_random_salt();
    let iv = gen_random_iv();
    let plaintext = b"forensic evidence payload".repeat(4);

    let ciphertext =
        encrypt_argon2_aes256cbc(8, 1, 1, &salt, &iv, "correct horse", &plaintext).unwrap();
    let decrypted =
        decrypt_argon2_aes256cbc(8, 1, 1, &salt, &iv, "correct horse", &ciphertext).unwrap();

    assert_ne!(ciphertext, plaintext);
    assert_eq!(decrypted, plaintext);
}

#[test]
fn argon2_aes128cbc_roundtrip() {
    let salt = gen_random_salt();
    let iv = gen_random_iv();
    let plaintext = b"another payload".repeat(8);

    let ciphertext = encrypt_argon2_aes128cbc(8, 1, 1, &salt, &iv, "hunter2", &plaintext).unwrap();
    let decrypted = decrypt_argon2_aes128cbc(8, 1, 1, &salt, &iv, "hunter2", &ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn pbe_decryption_with_wrong_password_does_not_return_the_plaintext() {
    let salt = gen_random_salt();
    let iv = gen_random_iv();
    let plaintext = b"do not leak me".repeat(4);
    let ciphertext =
        encrypt_argon2_aes256cbc(8, 1, 1, &salt, &iv, "right password", &plaintext).unwrap();

    // PKCS7 unpadding usually rejects a wrong key, but a wrong password must
    // never yield the plaintext even when the padding happens to validate.
    if let Ok(decrypted) =
        decrypt_argon2_aes256cbc(8, 1, 1, &salt, &iv, "wrong password", &ciphertext)
    {
        assert_ne!(decrypted, plaintext);
    }
}

#[test]
fn scrypt_and_pbkdf2_pbe_roundtrip() {
    let salt = gen_random_salt();
    let iv = gen_random_iv();
    let plaintext = b"kdf scheme coverage".repeat(4);

    let scrypt_ciphertext =
        encrypt_scrypt_aes256cbc(2, 1, 1, &salt, iv, "password", &plaintext).unwrap();
    assert_eq!(
        decrypt_scrypt_aes256cbc(2, 1, 1, &salt, iv, "password", &scrypt_ciphertext).unwrap(),
        plaintext
    );

    let pbkdf2_ciphertext =
        encrypt_pbkdf2sha256_aes256cbc(1000, &salt, iv, "password", &plaintext).unwrap();
    assert_eq!(
        decrypt_pbkdf2sha256_aes256cbc(1000, &salt, iv, "password", &pbkdf2_ciphertext).unwrap(),
        plaintext
    );
}

#[test]
fn encryption_header_key_unwrapping_roundtrip() {
    let (mut encryption_header, encryption_key) =
        encryption_header_with_password(EncryptionAlgorithm::AES256GCM, "container-password");

    // Before unwrapping, the plain key must not be available.
    assert!(encryption_header.get_encryption_key().is_none());

    let unwrapped = encryption_header
        .decrypt_encryption_key("container-password")
        .unwrap();

    assert_eq!(unwrapped, encryption_key);
}

#[test]
fn encryption_header_key_unwrapping_rejects_a_wrong_password() {
    let (mut encryption_header, _) =
        encryption_header_with_password(EncryptionAlgorithm::AES256GCM, "container-password");

    let result = encryption_header.decrypt_encryption_key("not-the-password");

    assert!(result.is_err());
}

#[test]
fn aead_roundtrip_for_every_supported_algorithm() {
    let message = b"chunk payload".repeat(16);
    for (algorithm, key_len) in [
        (EncryptionAlgorithm::AES128GCM, 16),
        (EncryptionAlgorithm::AES256GCM, 32),
        (EncryptionAlgorithm::CHACHA20POLY1305, 32),
    ] {
        let key = gen_random_key(key_len * 8);
        let ciphertext = Vec::<u8>::encrypt(&key, &message, 1, &algorithm).unwrap();
        assert_ne!(ciphertext, message);

        let decrypted = Vec::<u8>::decrypt(&key, &ciphertext, 1, &algorithm).unwrap();
        assert_eq!(decrypted, message);

        // The nonce is derived from the chunk number, so decrypting with a
        // different chunk number must fail the AEAD tag check.
        assert!(Vec::<u8>::decrypt(&key, &ciphertext, 2, &algorithm).is_err());
    }
}

#[test]
fn aead_detects_a_modified_ciphertext() {
    let key = gen_random_key(256);
    let message = b"tamper detection".repeat(8);
    let mut ciphertext =
        Vec::<u8>::encrypt(&key, &message, 7, EncryptionAlgorithm::AES256GCM).unwrap();
    ciphertext[0] ^= 0xFF;

    let result = Vec::<u8>::decrypt(&key, &ciphertext, 7, EncryptionAlgorithm::AES256GCM);

    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

#[test]
fn ed25519_signature_roundtrip() {
    let signing_key = Signature::new_signing_key();
    let message = b"hash value of an acquired object";

    let signature = Signature::sign(&signing_key, message);

    assert!(Signature::verify(signing_key.verifying_key().to_bytes(), message, signature).unwrap());
}

#[test]
fn ed25519_verification_fails_for_a_modified_message() {
    let signing_key = Signature::new_signing_key();
    let signature = Signature::sign(&signing_key, b"original message");

    let verified = Signature::verify(
        signing_key.verifying_key().to_bytes(),
        b"modified message",
        signature,
    )
    .unwrap();

    assert!(!verified);
}

#[test]
fn ed25519_verification_fails_for_a_foreign_key() {
    let signing_key = Signature::new_signing_key();
    let foreign_key = Signature::new_signing_key();
    let message = b"hash value of an acquired object";
    let signature = Signature::sign(&signing_key, message);

    let verified =
        Signature::verify(foreign_key.verifying_key().to_bytes(), message, signature).unwrap();

    assert!(!verified);
}

// ---------------------------------------------------------------------------
// Encrypted containers
// ---------------------------------------------------------------------------

/// Builds a physical object header whose payload is encrypted with the given
/// algorithm, unlocked by `password`.
fn encrypted_physical_object_header(
    object_number: u64,
    chunk_size: u64,
    algorithm: EncryptionAlgorithm,
    password: &str,
) -> ObjectHeader {
    let (mut encryption_header, _) = encryption_header_with_password(algorithm, password);
    // The writer encrypts with the unwrapped key, so it has to be present.
    encryption_header.decrypt_encryption_key(password).unwrap();
    ObjectHeader::new(
        object_number,
        Some(encryption_header),
        chunk_size,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
        DescriptionHeader::new_empty(),
        ObjectType::Physical,
        ObjectFlags {
            encryption: true,
            sign_hash: false,
            passive_object: false,
        },
    )
}

#[test]
fn encrypted_physical_object_roundtrip_for_every_algorithm() {
    for algorithm in [
        EncryptionAlgorithm::AES128GCM,
        EncryptionAlgorithm::AES256GCM,
        EncryptionAlgorithm::CHACHA20POLY1305,
    ] {
        let input = b"encrypted acquisition payload ".repeat(32);
        let object_header = encrypted_physical_object_header(1, 64, algorithm, "s3cret");
        let container = encode_physical_container(vec![(object_header, input.clone())]);

        // The raw container must not expose the plaintext.
        assert!(
            !container
                .windows(input.len())
                .any(|window| window == input.as_slice())
        );

        let mut reader = ZffReader::with_reader(vec![Mutex::new(Cursor::new(container))]).unwrap();
        assert_eq!(
            reader.list_objects().unwrap().get(&1),
            Some(&ReaderObjectType::Encrypted)
        );

        reader.initialize_object(1).unwrap();
        assert_eq!(
            reader.decrypt_object(1, "s3cret").unwrap(),
            ReaderObjectType::Physical
        );
        reader.set_active_object(1).unwrap();

        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();

        assert_eq!(output, input);
    }
}

#[test]
fn encrypted_object_cannot_be_decrypted_with_a_wrong_password() {
    let input = b"encrypted acquisition payload ".repeat(16);
    let object_header =
        encrypted_physical_object_header(1, 64, EncryptionAlgorithm::AES256GCM, "s3cret");
    let container = encode_physical_container(vec![(object_header, input)]);

    let mut reader = ZffReader::with_reader(vec![Mutex::new(Cursor::new(container))]).unwrap();
    reader.initialize_object(1).unwrap();

    assert!(reader.decrypt_object(1, "wrong-password").is_err());
}

#[test]
fn encrypted_object_cannot_be_read_before_it_is_decrypted() {
    let input = b"encrypted acquisition payload ".repeat(16);
    let object_header =
        encrypted_physical_object_header(1, 64, EncryptionAlgorithm::AES256GCM, "s3cret");
    let container = encode_physical_container(vec![(object_header, input)]);

    let mut reader = ZffReader::with_reader(vec![Mutex::new(Cursor::new(container))]).unwrap();
    reader.initialize_object(1).unwrap();
    reader.set_active_object(1).unwrap();

    let mut output = Vec::new();
    assert!(reader.read_to_end(&mut output).is_err());
}

#[test]
fn encrypted_and_compressed_object_roundtrip() {
    let input = b"compressible encrypted payload ".repeat(128);
    let mut object_header =
        encrypted_physical_object_header(1, 128, EncryptionAlgorithm::AES256GCM, "s3cret");
    object_header.compression_header = CompressionHeader::new(CompressionAlgorithm::Zstd, 3, 1.01);
    let container = encode_physical_container(vec![(object_header, input.clone())]);

    let mut reader = ZffReader::with_reader(vec![Mutex::new(Cursor::new(container))]).unwrap();
    reader.initialize_object(1).unwrap();
    reader.decrypt_object(1, "s3cret").unwrap();
    reader.set_active_object(1).unwrap();

    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();

    assert_eq!(output, input);
}

// ---------------------------------------------------------------------------
// Hashing, signatures and integrity of a written container
// ---------------------------------------------------------------------------

/// Encodes a single physical object and returns the container together with the
/// object footer, so that the recorded hashes can be inspected.
fn encode_physical_container_with_params(
    objects: Vec<(ObjectHeader, Vec<u8>)>,
    hash_types: Vec<HashType>,
    params: ZffCreationParameters<Mutex<Cursor<Vec<u8>>>>,
) -> Vec<u8> {
    let mut physical_objects = HashMap::new();
    for (object_header, input) in objects {
        physical_objects.insert(object_header, Cursor::new(input));
    }

    let mut writer: TestZffWriter = ZffWriter::new(
        physical_objects,
        HashMap::new(),
        HashMap::new(),
        hash_types,
        params,
        ZffFilesOutput::Stream,
    )
    .unwrap();
    let mut container = Vec::new();
    writer.read_to_end(&mut container).unwrap();
    container
}

#[test]
fn recorded_hashes_match_the_acquired_data() {
    let input = b"data whose digests are recorded".repeat(32);
    let object_header = physical_object_header(
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let container = encode_physical_container_with_params(
        vec![(object_header, input.clone())],
        vec![HashType::Blake3, HashType::SHA256],
        default_creation_parameters(),
    );
    let mut reader = initialized_reader(container);
    reader.set_active_object(1).unwrap();

    let footer = match reader.object_footer(1).unwrap() {
        ObjectFooter::Physical(footer) => footer,
        other => panic!("expected a physical object footer, got {other:?}"),
    };

    assert_eq!(footer.length_of_data, input.len() as u64);
    assert!(!footer.hash_header.hashes.is_empty());
    for hash_value in &footer.hash_header.hashes {
        let mut hasher = Hash::new_hasher(hash_value.hash_type());
        hasher.update(&input);
        assert_eq!(
            hash_value.hash(),
            &hasher.finalize().to_vec(),
            "digest mismatch for {:?}",
            hash_value.hash_type()
        );
        // No signing key was configured, so no signature may be present.
        assert!(hash_value.ed25519_signature().is_none());
    }
}

#[test]
fn recorded_hashes_are_signed_when_a_signing_key_is_configured() {
    let input = b"signed acquisition".repeat(32);
    let signing_key = Signature::new_signing_key();
    let verifying_key = signing_key.verifying_key().to_bytes();
    let mut object_header = physical_object_header(
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    object_header.flags.sign_hash = true;
    let params = ZffCreationParameters {
        signature_key: Some(signing_key),
        ..default_creation_parameters()
    };
    let container = encode_physical_container_with_params(
        vec![(object_header, input)],
        vec![HashType::Blake3],
        params,
    );
    let mut reader = initialized_reader(container);
    reader.set_active_object(1).unwrap();

    let footer = match reader.object_footer(1).unwrap() {
        ObjectFooter::Physical(footer) => footer,
        other => panic!("expected a physical object footer, got {other:?}"),
    };

    assert!(!footer.hash_header.hashes.is_empty());
    for hash_value in &footer.hash_header.hashes {
        let signature = hash_value
            .ed25519_signature()
            .expect("a signature was requested but is missing");
        assert!(
            Signature::verify(verifying_key, hash_value.hash(), signature).unwrap(),
            "the recorded signature does not verify against the recorded hash"
        );
    }
}

#[test]
fn a_truncated_container_is_rejected() {
    let input = b"truncation detection".repeat(64);
    let object_header = physical_object_header(
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let container = encode_physical_container(vec![(object_header, input)]);
    let truncated = container[..container.len() / 2].to_vec();

    let result = ZffReader::with_reader(vec![Mutex::new(Cursor::new(truncated))]);

    assert!(result.is_err());
}

#[test]
fn a_container_with_a_corrupted_footer_is_rejected() {
    let input = b"footer corruption detection".repeat(64);
    let object_header = physical_object_header(
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let mut container = encode_physical_container(vec![(object_header, input)]);
    // Overwrite the tail, which carries the main footer.
    let tail_start = container.len() - 16;
    container[tail_start..].fill(0xFF);

    let result = ZffReader::with_reader(vec![Mutex::new(Cursor::new(container))]);

    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Segmentation
// ---------------------------------------------------------------------------

/// Encodes the given physical objects into a segmented container and returns one
/// buffer per segment. This mirrors what [ZffWriter::generate_files] does for
/// on-disk containers, but keeps every segment in memory.
fn encode_segmented_container(
    objects: Vec<(ObjectHeader, Vec<u8>)>,
    target_segment_size: u64,
) -> Vec<Vec<u8>> {
    let mut physical_objects = HashMap::new();
    for (object_header, input) in objects {
        physical_objects.insert(object_header, Cursor::new(input));
    }

    let params = ZffCreationParameters {
        target_segment_size: Some(target_segment_size),
        ..default_creation_parameters()
    };
    let mut writer: TestZffWriter = ZffWriter::new(
        physical_objects,
        HashMap::new(),
        HashMap::new(),
        vec![HashType::Blake3],
        params,
        ZffFilesOutput::Stream,
    )
    .unwrap();

    let mut segments = Vec::new();
    loop {
        let mut segment = Vec::new();
        let mut buffer = vec![0u8; 1024];
        loop {
            match writer.read(&mut buffer).unwrap() {
                0 => break,
                n => segment.extend_from_slice(&buffer[..n]),
            }
        }
        segments.push(segment);

        match writer.next_segment() {
            SegmentationState::LastSegmentFinished => break,
            SegmentationState::SegmentFinished => (),
            SegmentationState::SegmentNotFinished => {
                panic!("the writer reported an unfinished segment after a complete read")
            }
        }
    }
    segments
}

fn reader_over_segments(segments: Vec<Vec<u8>>) -> ZffReader<Mutex<Cursor<Vec<u8>>>> {
    let readers = segments
        .into_iter()
        .map(|segment| Mutex::new(Cursor::new(segment)))
        .collect();
    let mut reader = ZffReader::with_reader(readers).unwrap();
    reader.initialize_objects_all().unwrap();
    reader
}

#[test]
fn a_segmented_container_roundtrips_across_segments() {
    let input: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    let object_header = physical_object_header(
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let segments = encode_segmented_container(vec![(object_header, input.clone())], 2048);

    assert!(
        segments.len() > 1,
        "expected the container to be split, got {} segment(s)",
        segments.len()
    );

    let mut reader = reader_over_segments(segments);
    reader.set_active_object(1).unwrap();
    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();

    assert_eq!(output, input);
}

#[test]
fn a_smaller_target_segment_size_produces_more_segments() {
    let input: Vec<u8> = (0..16384u32).map(|i| (i % 251) as u8).collect();
    let segment_counts: Vec<usize> = [16384, 4096, 2048]
        .into_iter()
        .map(|target_segment_size| {
            let object_header = physical_object_header(
                128,
                CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
            );
            encode_segmented_container(vec![(object_header, input.clone())], target_segment_size)
                .len()
        })
        .collect();

    assert!(
        segment_counts.windows(2).all(|pair| pair[0] < pair[1]),
        "expected strictly more segments for smaller targets, got {segment_counts:?}"
    );
}

#[test]
fn no_segment_exceeds_the_target_segment_size() {
    let input: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();

    for target_segment_size in [4096, 8192, 16384, 32768] {
        for chunk_size in [64, 128, 512] {
            let object_header = physical_object_header(
                chunk_size,
                CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
            );
            let segments = encode_segmented_container(
                vec![(object_header, input.clone())],
                target_segment_size,
            );

            assert!(segments.len() > 1);
            for (index, segment) in segments.iter().enumerate() {
                assert!(
                    segment.len() as u64 <= target_segment_size,
                    "segment {index} of {} is {} bytes, target was {target_segment_size} \
                     (chunk size {chunk_size})",
                    segments.len(),
                    segment.len()
                );
            }
        }
    }
}

#[test]
fn no_segment_exceeds_the_target_when_compressed_or_deduplicated() {
    // Compression, deduplication and same-byte chunks all change how much a
    // chunk contributes to a segment; the cap has to hold for each of them.
    let compressible = b"a highly compressible run of bytes ".repeat(2048);
    let same_bytes = vec![0xAA; 65536];
    let duplicated = repeating_chunks_input(128, 4, 128);
    let target_segment_size = 8192;

    for (label, input, compression) in [
        (
            "compressed",
            compressible,
            CompressionHeader::new(CompressionAlgorithm::Zstd, 3, 1.01),
        ),
        (
            "same bytes",
            same_bytes,
            CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
        ),
        (
            "duplicated",
            duplicated,
            CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
        ),
    ] {
        let object_header = physical_object_header(128, compression);
        let segments =
            encode_segmented_container(vec![(object_header, input)], target_segment_size);

        for (index, segment) in segments.iter().enumerate() {
            assert!(
                segment.len() as u64 <= target_segment_size,
                "{label}: segment {index} is {} bytes, target was {target_segment_size}",
                segment.len()
            );
        }
    }
}

#[test]
fn no_segment_exceeds_the_target_with_several_objects_of_different_chunk_sizes() {
    // The next chunk may belong to the next object, which can use a larger chunk
    // size than the object currently being written.
    let first_input: Vec<u8> = (0..32768u32).map(|i| (i % 251) as u8).collect();
    let second_input: Vec<u8> = (0..32768u32).map(|i| (i % 241) as u8).collect();
    let target_segment_size = 8192;

    let segments = encode_segmented_container(
        vec![
            (
                physical_object_header_with_number(
                    1,
                    64,
                    CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
                ),
                first_input.clone(),
            ),
            (
                physical_object_header_with_number(
                    2,
                    2048,
                    CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
                ),
                second_input.clone(),
            ),
        ],
        target_segment_size,
    );

    for (index, segment) in segments.iter().enumerate() {
        assert!(
            segment.len() as u64 <= target_segment_size,
            "segment {index} is {} bytes, target was {target_segment_size}",
            segment.len()
        );
    }

    // The cap must not cost correctness.
    let mut reader = reader_over_segments(segments);
    let mut outputs = Vec::new();
    for object_number in [1, 2] {
        reader.set_active_object(object_number).unwrap();
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        outputs.push(output);
    }
    assert!(outputs.contains(&first_input));
    assert!(outputs.contains(&second_input));
}

#[test]
fn a_segmented_container_with_several_objects_roundtrips() {
    let first_input: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let second_input: Vec<u8> = (0..4096u32).map(|i| (i % 241) as u8).collect();
    let first_header = physical_object_header_with_number(
        1,
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let second_header = physical_object_header_with_number(
        2,
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let segments = encode_segmented_container(
        vec![
            (first_header, first_input.clone()),
            (second_header, second_input.clone()),
        ],
        2048,
    );
    assert!(segments.len() > 1);

    let mut reader = reader_over_segments(segments);
    let mut outputs = Vec::new();
    for object_number in [1, 2] {
        reader.set_active_object(object_number).unwrap();
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        outputs.push(output);
    }

    assert!(outputs.contains(&first_input));
    assert!(outputs.contains(&second_input));
}

#[test]
fn a_segmented_container_is_unreadable_when_a_segment_is_missing() {
    let input: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    let object_header = physical_object_header(
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let mut segments = encode_segmented_container(vec![(object_header, input)], 2048);
    assert!(segments.len() > 2);
    // Drop a segment from the middle; the data it carried must not be readable.
    segments.remove(1);

    let readers = segments
        .into_iter()
        .map(|segment| Mutex::new(Cursor::new(segment)))
        .collect();
    let mut reader = ZffReader::with_reader(readers).unwrap();
    reader.initialize_objects_all().unwrap();
    reader.set_active_object(1).unwrap();

    let mut output = Vec::new();
    assert!(reader.read_to_end(&mut output).is_err());
}

// ---------------------------------------------------------------------------
// Logical objects
// ---------------------------------------------------------------------------

/// A [LogicalObjectSource] backed by in-memory entries.
///
/// This lets the logical encoding path be tested without touching the
/// filesystem, so the tests stay hermetic and platform independent.
struct InMemoryLogicalSource {
    entries: Vec<(FileTypeEncodingInformation, FileHeader)>,
    iterator_index: usize,
    root_dir_filenumbers: Vec<u64>,
    symlink_real_paths: HashMap<u64, PathBuf>,
    hardlink_map: HashMap<u64, u64>,
    directory_children: HashMap<u64, Vec<u64>>,
}

impl InMemoryLogicalSource {
    fn new(
        entries: Vec<(FileTypeEncodingInformation, FileHeader)>,
        root_dir_filenumbers: Vec<u64>,
        directory_children: HashMap<u64, Vec<u64>>,
    ) -> Self {
        Self {
            entries,
            iterator_index: 0,
            root_dir_filenumbers,
            symlink_real_paths: HashMap::new(),
            hardlink_map: HashMap::new(),
            directory_children,
        }
    }
}

impl Iterator for InMemoryLogicalSource {
    type Item = Result<(FileTypeEncodingInformation, FileHeader)>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.iterator_index >= self.entries.len() {
            return None;
        }
        // FileTypeEncodingInformation carries a boxed reader and is therefore
        // not cloneable; swap the entry out instead of copying it.
        let placeholder = (
            FileTypeEncodingInformation::Directory(Vec::new()),
            self.entries[self.iterator_index].1.clone(),
        );
        let entry = std::mem::replace(&mut self.entries[self.iterator_index], placeholder);
        self.iterator_index += 1;
        Some(Ok(entry))
    }
}

impl LogicalObjectSource for InMemoryLogicalSource {
    fn remaining_elements(&self) -> u64 {
        (self.entries.len() - self.iterator_index) as u64
    }

    fn root_dir_filenumbers(&self) -> &Vec<u64> {
        &self.root_dir_filenumbers
    }

    fn symlink_real_paths(&self) -> &HashMap<u64, PathBuf> {
        &self.symlink_real_paths
    }

    fn hardlink_map(&self) -> &HashMap<u64, u64> {
        &self.hardlink_map
    }

    fn directory_children(&self) -> &HashMap<u64, Vec<u64>> {
        &self.directory_children
    }
}

fn file_header(file_number: u64, file_type: FileType, name: &str, parent: u64) -> FileHeader {
    FileHeader::new(
        file_number,
        file_type,
        PlatformString::from(OsString::from(name)),
        parent,
        HashMap::new(),
    )
}

fn logical_object_header(object_number: u64, chunk_size: u64) -> ObjectHeader {
    ObjectHeader::new(
        object_number,
        None,
        chunk_size,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
        DescriptionHeader::new_empty(),
        ObjectType::Logical,
        ObjectFlags::default(),
    )
}

fn encode_logical_container(object_header: ObjectHeader, source: InMemoryLogicalSource) -> Vec<u8> {
    let mut logical_objects: HashMap<ObjectHeader, Box<dyn LogicalObjectSource>> = HashMap::new();
    logical_objects.insert(object_header, Box::new(source));

    let mut writer: TestZffWriter = ZffWriter::new(
        HashMap::new(),
        logical_objects,
        HashMap::new(),
        vec![HashType::Blake3],
        default_creation_parameters(),
        ZffFilesOutput::Stream,
    )
    .unwrap();
    let mut container = Vec::new();
    writer.read_to_end(&mut container).unwrap();
    container
}

#[test]
fn logical_object_with_a_single_file_roundtrips() {
    let content = b"contents of a logically acquired file".repeat(8);
    let source = InMemoryLogicalSource::new(
        vec![(
            FileTypeEncodingInformation::File(Box::new(Cursor::new(content.clone()))),
            file_header(1, FileType::File, "evidence.txt", 0),
        )],
        vec![1],
        HashMap::new(),
    );
    let container = encode_logical_container(logical_object_header(1, 64), source);

    let mut reader = initialized_reader(container);
    assert_eq!(
        reader.list_objects().unwrap().get(&1),
        Some(&ReaderObjectType::Logical)
    );
    reader.set_active_object(1).unwrap();
    reader.set_active_file(1).unwrap();

    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();

    assert_eq!(output, content);
    assert_eq!(
        reader.current_fileheader().unwrap().filename,
        PlatformString::from(OsString::from("evidence.txt"))
    );
}

#[test]
fn logical_object_with_a_directory_tree_roundtrips() {
    let first_content = b"first file".repeat(16);
    let second_content = b"second file".repeat(16);
    let mut directory_children = HashMap::new();
    directory_children.insert(1, vec![2, 3]);

    let source = InMemoryLogicalSource::new(
        vec![
            (
                FileTypeEncodingInformation::Directory(vec![2, 3]),
                file_header(1, FileType::Directory, "evidence", 0),
            ),
            (
                FileTypeEncodingInformation::File(Box::new(Cursor::new(first_content.clone()))),
                file_header(2, FileType::File, "first.txt", 1),
            ),
            (
                FileTypeEncodingInformation::File(Box::new(Cursor::new(second_content.clone()))),
                file_header(3, FileType::File, "second.txt", 1),
            ),
        ],
        vec![1],
        directory_children,
    );
    let container = encode_logical_container(logical_object_header(1, 64), source);

    let mut reader = initialized_reader(container);
    reader.set_active_object(1).unwrap();

    reader.set_active_file(2).unwrap();
    let mut first_output = Vec::new();
    reader.read_to_end(&mut first_output).unwrap();
    assert_eq!(first_output, first_content);

    reader.set_active_file(3).unwrap();
    let mut second_output = Vec::new();
    reader.read_to_end(&mut second_output).unwrap();
    assert_eq!(second_output, second_content);

    // The parent relation has to survive the roundtrip.
    reader.set_active_file(2).unwrap();
    assert_eq!(reader.current_fileheader().unwrap().parent_file_number, 1);
}

#[test]
fn logical_object_preserves_an_empty_file() {
    let source = InMemoryLogicalSource::new(
        vec![(
            FileTypeEncodingInformation::File(Box::new(Cursor::new(Vec::new()))),
            file_header(1, FileType::File, "empty.bin", 0),
        )],
        vec![1],
        HashMap::new(),
    );
    let container = encode_logical_container(logical_object_header(1, 64), source);

    let mut reader = initialized_reader(container);
    reader.set_active_object(1).unwrap();
    reader.set_active_file(1).unwrap();

    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();

    assert!(output.is_empty());
    assert_eq!(reader.current_filemetadata().unwrap().length_of_data(), 0);
}

#[test]
fn logical_object_rejects_an_unknown_file_number() {
    let source = InMemoryLogicalSource::new(
        vec![(
            FileTypeEncodingInformation::File(Box::new(Cursor::new(b"data".to_vec()))),
            file_header(1, FileType::File, "evidence.txt", 0),
        )],
        vec![1],
        HashMap::new(),
    );
    let container = encode_logical_container(logical_object_header(1, 64), source);

    let mut reader = initialized_reader(container);
    reader.set_active_object(1).unwrap();

    assert!(reader.set_active_file(9999).is_err());
}

// ---------------------------------------------------------------------------
// Deduplication
// ---------------------------------------------------------------------------

fn deduplication_parameters() -> ZffCreationParameters<Mutex<Cursor<Vec<u8>>>> {
    ZffCreationParameters {
        deduplication_metadata: Some(DeduplicationMetadata {
            deduplication_map: DeduplicationChunkMap::new_in_memory_map(),
            original_zffreader: None,
        }),
        ..default_creation_parameters()
    }
}

/// Builds an input whose chunks repeat, so deduplication has something to find.
fn repeating_chunks_input(chunk_size: usize, distinct_chunks: usize, repeats: usize) -> Vec<u8> {
    let mut input = Vec::new();
    for _ in 0..repeats {
        for chunk in 0..distinct_chunks {
            input.extend(std::iter::repeat_n(chunk as u8, chunk_size));
        }
    }
    input
}

#[test]
fn deduplicated_container_roundtrips_exactly() {
    let chunk_size = 64;
    let input = repeating_chunks_input(chunk_size, 4, 8);
    let object_header = physical_object_header(
        chunk_size as u64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let container = encode_physical_container_with_params(
        vec![(object_header, input.clone())],
        vec![HashType::Blake3],
        deduplication_parameters(),
    );

    let mut reader = initialized_reader(container);
    reader.set_active_object(1).unwrap();
    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();

    assert_eq!(output, input);
}

#[test]
fn deduplication_reduces_the_container_size_for_repeating_data() {
    // Chunks large enough that the saved payload clearly outweighs the per-chunk
    // metadata that every container carries regardless of deduplication.
    let chunk_size = 1024;
    // Varied chunk bodies, so the same-bytes optimisation cannot shrink them and
    // any size difference is attributable to deduplication.
    let distinct: Vec<Vec<u8>> = (0..4u8)
        .map(|seed| {
            (0..chunk_size)
                .map(|i| {
                    (i as u8)
                        .wrapping_mul(31)
                        .wrapping_add(seed.wrapping_mul(97))
                })
                .collect()
        })
        .collect();
    let mut input = Vec::new();
    for _ in 0..16 {
        for chunk in &distinct {
            input.extend_from_slice(chunk);
        }
    }

    let plain = encode_physical_container_with_params(
        vec![(
            physical_object_header(
                chunk_size as u64,
                CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
            ),
            input.clone(),
        )],
        vec![HashType::Blake3],
        default_creation_parameters(),
    );
    let deduplicated = encode_physical_container_with_params(
        vec![(
            physical_object_header(
                chunk_size as u64,
                CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
            ),
            input.clone(),
        )],
        vec![HashType::Blake3],
        deduplication_parameters(),
    );

    assert!(
        deduplicated.len() < plain.len(),
        "deduplicated container is {} bytes, plain container is {} bytes",
        deduplicated.len(),
        plain.len()
    );

    // Size is only useful if the data still reads back correctly.
    let mut reader = initialized_reader(deduplicated);
    reader.set_active_object(1).unwrap();
    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();
    assert_eq!(output, input);
}

#[test]
fn deduplicated_container_supports_read_at_across_duplicate_chunks() {
    let chunk_size = 16;
    let input = repeating_chunks_input(chunk_size, 2, 8);
    let object_header = physical_object_header(
        chunk_size as u64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let container = encode_physical_container_with_params(
        vec![(object_header, input.clone())],
        vec![HashType::Blake3],
        deduplication_parameters(),
    );
    let reader = initialized_reader(container);

    // Start inside a duplicate chunk and read across several chunk boundaries.
    let mut output = vec![0; 40];
    let read = reader.read_at(&mut output, 1, 0, 37).unwrap();

    assert_eq!(read, output.len());
    assert_eq!(output, input[37..77]);
}

// ---------------------------------------------------------------------------
// Same-byte chunks
// ---------------------------------------------------------------------------

#[test]
fn same_byte_chunks_roundtrip() {
    let chunk_size = 64;
    // A run of identical bytes is stored as a single byte plus a flag.
    let mut input = vec![0xAA; chunk_size * 4];
    input.extend_from_slice(&[0x01; 32]);
    let object_header = physical_object_header(
        chunk_size as u64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let container = encode_physical_container(vec![(object_header, input.clone())]);

    let mut reader = initialized_reader(container);
    reader.set_active_object(1).unwrap();
    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();

    assert_eq!(output, input);
}

#[test]
fn a_container_of_same_byte_chunks_is_much_smaller_than_its_payload() {
    // Each identical chunk collapses to a single byte plus a flag. The chunk
    // size has to be well above the per-chunk metadata for that to show up in
    // the container size.
    let chunk_size = 4096;
    let input = vec![0xAA; chunk_size * 64];
    let object_header = physical_object_header(
        chunk_size as u64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );

    let container = encode_physical_container(vec![(object_header, input.clone())]);

    assert!(
        container.len() < input.len(),
        "container is {} bytes for {} bytes of identical payload",
        container.len(),
        input.len()
    );
}

// ---------------------------------------------------------------------------
// Format compatibility (golden files)
// ---------------------------------------------------------------------------

// A container written by zff 3.0.0, committed to the repository. It pins the
// on-disk format: if a change makes this crate unable to read containers that
// earlier versions produced, these tests fail.
//
// Byte-for-byte comparison is deliberately not asserted -- object footers record
// acquisition timestamps, so two runs over the same input never produce
// identical bytes. What has to stay stable is that the container remains
// readable and returns the same data.
//
// To add a fixture for a new format version, write a container with the writer
// of that version and commit it next to this one; never regenerate an existing
// fixture, since that would defeat its purpose.
const GOLDEN_V3_PHYSICAL: &[u8] = include_bytes!("testdata/golden_v3_physical.zff");

#[test]
fn a_container_written_by_zff_3_0_0_is_still_readable() {
    let mut reader =
        ZffReader::with_reader(vec![Mutex::new(Cursor::new(GOLDEN_V3_PHYSICAL.to_vec()))]).unwrap();

    let objects = reader.list_objects().unwrap();
    assert_eq!(objects.get(&1), Some(&ReaderObjectType::Physical));
    assert_eq!(objects.get(&2), Some(&ReaderObjectType::Physical));

    reader.initialize_objects_all().unwrap();

    reader.set_active_object(1).unwrap();
    let mut uncompressed = Vec::new();
    reader.read_to_end(&mut uncompressed).unwrap();
    assert_eq!(uncompressed, b"golden fixture physical payload ".repeat(64));

    reader.set_active_object(2).unwrap();
    let mut compressed = Vec::new();
    reader.read_to_end(&mut compressed).unwrap();
    assert_eq!(compressed, b"golden fixture compressed payload ".repeat(64));
}

#[test]
fn the_golden_container_still_carries_its_metadata_and_hashes() {
    let mut reader =
        ZffReader::with_reader(vec![Mutex::new(Cursor::new(GOLDEN_V3_PHYSICAL.to_vec()))]).unwrap();
    reader.initialize_objects_all().unwrap();
    reader.set_active_object(1).unwrap();

    let object_header = reader.active_object_header_ref().unwrap();
    assert_eq!(object_header.chunk_size, 128);
    assert_eq!(
        object_header.description_header.case_number(),
        Some("golden-1")
    );

    let footer = match reader.object_footer(1).unwrap() {
        ObjectFooter::Physical(footer) => footer,
        other => panic!("expected a physical object footer, got {other:?}"),
    };
    let expected = b"golden fixture physical payload ".repeat(64);
    assert_eq!(footer.length_of_data, expected.len() as u64);
    assert!(!footer.hash_header.hashes.is_empty());
    for hash_value in &footer.hash_header.hashes {
        let mut hasher = Hash::new_hasher(hash_value.hash_type());
        hasher.update(&expected);
        assert_eq!(
            hash_value.hash(),
            &hasher.finalize().to_vec(),
            "the digest recorded in the golden container no longer matches its data"
        );
    }
}

#[test]
fn the_golden_container_supports_random_access() {
    let mut reader =
        ZffReader::with_reader(vec![Mutex::new(Cursor::new(GOLDEN_V3_PHYSICAL.to_vec()))]).unwrap();
    reader.initialize_objects_all().unwrap();
    let expected = b"golden fixture physical payload ".repeat(64);

    let mut output = vec![0; 300];
    let read = reader.read_at(&mut output, 1, 0, 137).unwrap();

    assert_eq!(read, output.len());
    assert_eq!(output, expected[137..437]);
}

// ---------------------------------------------------------------------------
// Virtual objects
// ---------------------------------------------------------------------------

/// A [VirtualObjectSource] backed by in-memory entries, so the virtual encoding
/// path can be tested without a tar archive or the filesystem.
struct InMemoryVirtualSource {
    entries: Vec<(FileHeader, VirtualFileFooterMetadata)>,
    iterator_index: usize,
    root_dir_filenumbers: Vec<u64>,
}

impl InMemoryVirtualSource {
    fn new(
        entries: Vec<(FileHeader, VirtualFileFooterMetadata)>,
        root_dir_filenumbers: Vec<u64>,
    ) -> Self {
        Self {
            entries,
            iterator_index: 0,
            root_dir_filenumbers,
        }
    }
}

impl Iterator for InMemoryVirtualSource {
    type Item = Result<(FileHeader, VirtualFileFooterMetadata)>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.entries.get(self.iterator_index)?.clone();
        self.iterator_index += 1;
        Some(Ok(entry))
    }
}

impl VirtualObjectSource for InMemoryVirtualSource {
    fn remaining_elements(&self) -> u64 {
        (self.entries.len() - self.iterator_index) as u64
    }

    fn root_dir_filenumbers(&self) -> &Vec<u64> {
        &self.root_dir_filenumbers
    }
}

/// Builds a virtual file whose content is assembled from the given extents.
fn virtual_file(
    file_number: u64,
    name: &str,
    extents: Vec<(u64, VirtualFileExtent)>,
) -> (FileHeader, VirtualFileFooterMetadata) {
    let length_of_data = extents.iter().map(|(_, extent)| extent.length).sum();
    let extents = extents.into_iter().collect::<BTreeMap<_, _>>();
    let virtual_file_map = VirtualFileMap::new(file_number, extents);
    (
        file_header(file_number, FileType::File, name, 0),
        VirtualFileFooterMetadata::new(
            HashHeader::new(Vec::new()),
            length_of_data,
            VirtualFileContent::FileMap(virtual_file_map),
        ),
    )
}

/// Writes a container holding one physical source object (number 1) and one
/// virtual object (number 2) that references it.
fn encode_virtual_container(source_data: Vec<u8>, virtual_files: InMemoryVirtualSource) -> Vec<u8> {
    let mut physical_objects = HashMap::new();
    let mut source_header = physical_object_header_with_number(
        1,
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    source_header.flags.passive_object = true;
    physical_objects.insert(source_header, Cursor::new(source_data));

    let virtual_header = ObjectHeader::new(
        2,
        None,
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
        DescriptionHeader::new_empty(),
        ObjectType::Virtual,
        ObjectFlags::default(),
    );
    let mut virtual_objects: HashMap<ObjectHeader, Box<dyn VirtualObjectSource>> = HashMap::new();
    virtual_objects.insert(virtual_header, Box::new(virtual_files));

    let mut writer: TestZffWriter = ZffWriter::new(
        physical_objects,
        HashMap::new(),
        virtual_objects,
        vec![HashType::Blake3],
        default_creation_parameters(),
        ZffFilesOutput::Stream,
    )
    .unwrap();
    let mut container = Vec::new();
    writer.read_to_end(&mut container).unwrap();
    container
}

#[test]
fn virtual_object_reads_data_through_a_single_extent() {
    let source_data: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
    let virtual_files = InMemoryVirtualSource::new(
        vec![virtual_file(
            1,
            "view.bin",
            vec![(0, VirtualFileExtent::new(1, 0, 128, 200))],
        )],
        vec![1],
    );
    let container = encode_virtual_container(source_data.clone(), virtual_files);

    let mut reader = initialized_reader(container);
    assert_eq!(
        reader.list_objects().unwrap().get(&2),
        Some(&ReaderObjectType::Virtual)
    );
    reader.set_active_object(2).unwrap();
    reader.set_active_file(1).unwrap();

    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();

    assert_eq!(output, source_data[128..328]);
}

#[test]
fn virtual_object_assembles_data_from_several_extents() {
    let source_data: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
    // Deliberately out of order and crossing chunk boundaries of the source.
    let virtual_files = InMemoryVirtualSource::new(
        vec![virtual_file(
            1,
            "assembled.bin",
            vec![
                (0, VirtualFileExtent::new(1, 0, 900, 100)),
                (100, VirtualFileExtent::new(1, 0, 30, 70)),
                (170, VirtualFileExtent::new(1, 0, 500, 130)),
            ],
        )],
        vec![1],
    );
    let container = encode_virtual_container(source_data.clone(), virtual_files);

    let mut reader = initialized_reader(container);
    reader.set_active_object(2).unwrap();
    reader.set_active_file(1).unwrap();

    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();

    let mut expected = Vec::new();
    expected.extend_from_slice(&source_data[900..1000]);
    expected.extend_from_slice(&source_data[30..100]);
    expected.extend_from_slice(&source_data[500..630]);
    assert_eq!(output, expected);
}

#[test]
fn virtual_object_exposes_several_files() {
    let source_data: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
    let virtual_files = InMemoryVirtualSource::new(
        vec![
            virtual_file(
                1,
                "first.bin",
                vec![(0, VirtualFileExtent::new(1, 0, 0, 64))],
            ),
            virtual_file(
                2,
                "second.bin",
                vec![(0, VirtualFileExtent::new(1, 0, 256, 64))],
            ),
        ],
        vec![1, 2],
    );
    let container = encode_virtual_container(source_data.clone(), virtual_files);

    let mut reader = initialized_reader(container);
    reader.set_active_object(2).unwrap();

    reader.set_active_file(1).unwrap();
    let mut first = Vec::new();
    reader.read_to_end(&mut first).unwrap();
    assert_eq!(first, source_data[0..64]);

    reader.set_active_file(2).unwrap();
    let mut second = Vec::new();
    reader.read_to_end(&mut second).unwrap();
    assert_eq!(second, source_data[256..320]);
}

#[test]
fn virtual_object_rejects_an_extent_pointing_at_a_missing_object() {
    let source_data: Vec<u8> = (0..256u32).map(|i| (i % 251) as u8).collect();
    let virtual_files = InMemoryVirtualSource::new(
        vec![virtual_file(
            1,
            "dangling.bin",
            // Object 42 does not exist in this container.
            vec![(0, VirtualFileExtent::new(42, 0, 0, 64))],
        )],
        vec![1],
    );
    let container = encode_virtual_container(source_data, virtual_files);

    let mut reader = initialized_reader(container);
    reader.set_active_object(2).unwrap();
    reader.set_active_file(1).unwrap();

    let mut output = Vec::new();
    assert!(reader.read_to_end(&mut output).is_err());
}

#[test]
fn no_segment_exceeds_the_target_for_an_encrypted_object() {
    // Encryption adds an AEAD tag to every chunk and to every flushed chunkmap,
    // which is the tightest case for the segment size accounting.
    let input: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
    let target_segment_size = 8192;

    for algorithm in [
        EncryptionAlgorithm::AES128GCM,
        EncryptionAlgorithm::AES256GCM,
        EncryptionAlgorithm::CHACHA20POLY1305,
    ] {
        let object_header = encrypted_physical_object_header(1, 128, algorithm, "s3cret");
        let segments =
            encode_segmented_container(vec![(object_header, input.clone())], target_segment_size);

        assert!(segments.len() > 1);
        for (index, segment) in segments.iter().enumerate() {
            assert!(
                segment.len() as u64 <= target_segment_size,
                "segment {index} is {} bytes, target was {target_segment_size}",
                segment.len()
            );
        }

        // And the encrypted, segmented container still reads back correctly.
        let readers = segments
            .into_iter()
            .map(|segment| Mutex::new(Cursor::new(segment)))
            .collect();
        let mut reader = ZffReader::with_reader(readers).unwrap();
        reader.initialize_object(1).unwrap();
        reader.decrypt_object(1, "s3cret").unwrap();
        reader.set_active_object(1).unwrap();
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, input);
    }
}

#[test]
fn the_chunkmap_encoding_overhead_constant_is_an_upper_bound() {
    // The segment size cap reserves CHUNKMAP_ENCODING_OVERHEAD bytes on top of
    // the payload size a chunkmap reports. If the encoding ever grows beyond
    // that, the cap would silently start to overshoot, so it is pinned here.
    let key = gen_random_key(256);
    for entries in [1usize, 2, 17, 128] {
        let mut header_map = ChunkHeaderMap::new_empty(1);
        // A fresh map has a target size of 0 and would reject every entry; the
        // writer sets this from the configured chunkmap size.
        header_map.set_target_size(DEFAULT_CHUNKMAP_SIZE as usize);
        for chunk_no in 0..entries as u64 {
            let chunk_header = ChunkHeader::new(chunk_no * 64, 64, ChunkFlags::default(), chunk_no);
            assert!(header_map.add_chunk_entry(chunk_no, chunk_header));
        }

        let reported = header_map.current_size() as u64;
        let plain = header_map.encode_directly().len() as u64;
        assert!(
            plain <= reported + CHUNKMAP_ENCODING_OVERHEAD,
            "{entries} entries: plain encoding is {plain} bytes, \
             reported size {reported} + overhead {CHUNKMAP_ENCODING_OVERHEAD}"
        );

        let encrypted = header_map
            .encrypt_encoded_map(&key, EncryptionAlgorithm::AES256GCM, entries as u64)
            .unwrap()
            .len() as u64;
        assert!(
            encrypted <= reported + CHUNKMAP_ENCODING_OVERHEAD,
            "{entries} entries: encrypted encoding is {encrypted} bytes, \
             reported size {reported} + overhead {CHUNKMAP_ENCODING_OVERHEAD}"
        );
    }
}

#[test]
fn an_impossibly_small_target_segment_size_still_terminates() {
    // The target cannot be honoured below one chunk plus the segment metadata.
    // The writer has to keep making progress instead of looping or emitting
    // empty segments, so each segment then carries exactly one chunk.
    let input: Vec<u8> = (0..2048u32).map(|i| (i % 251) as u8).collect();
    let object_header = physical_object_header(
        512,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let segments = encode_segmented_container(vec![(object_header, input.clone())], 1);

    assert!(segments.iter().all(|segment| !segment.is_empty()));

    let mut reader = reader_over_segments(segments);
    reader.set_active_object(1).unwrap();
    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();

    assert_eq!(output, input);
}

#[test]
fn segment_footer_encoded_size_matches_the_real_encoding() {
    // The segment size cap uses the arithmetic size instead of encoding the
    // footer once per chunk. The two must agree exactly, or the cap silently
    // starts using a wrong reserve.
    let mut footer = SegmentFooter::new_empty();
    assert_eq!(footer.encoded_size(), footer.header_size());

    for entry in 1..8u64 {
        footer.object_header_offsets.insert(entry, entry * 100);
        footer.object_footer_offsets.insert(entry, entry * 200);
        footer.chunk_header_map_table.insert(entry, entry * 300);
        footer.chunk_samebytes_map_table.insert(entry, entry * 400);
        footer.chunk_dedup_map_table.insert(entry, entry * 500);
        footer.length_of_segment = entry * 4096;
        footer.first_chunk_number = entry;
        footer.footer_offset = entry * 64;

        assert_eq!(
            footer.encoded_size(),
            footer.header_size(),
            "mismatch with {entry} entries per map"
        );
        assert_eq!(footer.encoded_size(), footer.encode_directly().len());
    }
}

// ---------------------------------------------------------------------------
// Specification conformance
// ---------------------------------------------------------------------------
//
// The round-trip tests above only prove that this crate's writer and reader
// agree with each other. They would still pass if both deviated from the zff
// specification in the same way. The tests in this section instead assert the
// exact on-disk bytes against the layout tables of the zff v3 specification, so
// that a third-party implementation reading these containers stays possible.
//
// Every expectation below is transcribed from the specification wiki
// (Encoding.md, Header-layout.md, Footer-layout.md).

#[test]
fn magic_bytes_match_the_specification() {
    // Header-layout.md, "Magic bytes".
    assert_eq!(HEADER_IDENTIFIER_SEGMENT_HEADER, 0x7A66666D);
    assert_eq!(HEADER_IDENTIFIER_ENCRYPTION_HEADER, 0x7A666665);
    assert_eq!(HEADER_IDENTIFIER_PBE_HEADER, 0x7A666670);
    assert_eq!(HEADER_IDENTIFIER_COMPRESSION_HEADER, 0x7A666663);
    assert_eq!(HEADER_IDENTIFIER_DESCRIPTION_HEADER, 0x7A666664);
    assert_eq!(HEADER_IDENTIFIER_HASH_HEADER, 0x7A666668);
    assert_eq!(HEADER_IDENTIFIER_FILE_HEADER, 0x7A666666);
    assert_eq!(HEADER_IDENTIFIER_OBJECT_HEADER, 0x7A66664F);
    assert_eq!(HEADER_IDENTIFIER_CHUNK_HEADER, 0x7A666643);
    assert_eq!(HEADER_IDENTIFIER_CHUNK_OFFSET_MAP, 0x7A666678);
    assert_eq!(HEADER_IDENTIFIER_HASH_VALUE, 0x7A666648);
    assert_eq!(HEADER_IDENTIFIER_CHUNK_SAMEBYTES_MAP, 0x7A666653);
    assert_eq!(HEADER_IDENTIFIER_CHUNK_DEDUPLICATION_MAP, 0x7A666644);
}

#[test]
fn flag_values_match_the_specification() {
    // Header-layout.md, "Hash types flag".
    assert_eq!(HashType::Blake2b512 as u8, 0);
    assert_eq!(HashType::SHA256 as u8, 1);
    assert_eq!(HashType::SHA512 as u8, 2);
    assert_eq!(HashType::SHA3_256 as u8, 3);
    assert_eq!(HashType::Blake3 as u8, 4);

    // Header-layout.md, "compression algorithm flag".
    assert_eq!(CompressionAlgorithm::None as u8, 0);
    assert_eq!(CompressionAlgorithm::Zstd as u8, 1);
    assert_eq!(CompressionAlgorithm::Lz4 as u8, 2);

    // Header-layout.md, "Encryption algorithms".
    assert_eq!(EncryptionAlgorithm::AES128GCM as u8, 0);
    assert_eq!(EncryptionAlgorithm::AES256GCM as u8, 1);
    assert_eq!(EncryptionAlgorithm::CHACHA20POLY1305 as u8, 2);

    // Header-layout.md, "KDF Flag" and "Encryption scheme Flag".
    assert_eq!(KDFScheme::PBKDF2SHA256 as u8, 0);
    assert_eq!(KDFScheme::Scrypt as u8, 1);
    assert_eq!(KDFScheme::Argon2id as u8, 2);
    assert_eq!(PBEScheme::AES128CBC as u8, 0);
    assert_eq!(PBEScheme::AES256CBC as u8, 1);

    // Header-layout.md, "Object Type".
    assert_eq!(ObjectType::Physical as u8, 0);
    assert_eq!(ObjectType::Logical as u8, 1);
    assert_eq!(ObjectType::Virtual as u8, 2);

    // Header-layout.md, "File type flags".
    assert_eq!(FileType::File as u8, 1);
    assert_eq!(FileType::Directory as u8, 2);
    assert_eq!(FileType::Symlink as u8, 3);
    assert_eq!(FileType::Hardlink as u8, 4);
    assert_eq!(FileType::SpecialFile as u8, 5);
}

#[test]
fn object_flag_bits_match_the_specification() {
    // Header-layout.md, "Object Flags": encryption 0b001, sign hash 0b010,
    // passive object 0b100.
    let encrypted = ObjectFlags {
        encryption: true,
        sign_hash: false,
        passive_object: false,
    };
    let signed = ObjectFlags {
        encryption: false,
        sign_hash: true,
        passive_object: false,
    };
    let passive = ObjectFlags {
        encryption: false,
        sign_hash: false,
        passive_object: true,
    };
    assert_eq!(u8::from(&encrypted), 0b0000_0001);
    assert_eq!(u8::from(&signed), 0b0000_0010);
    assert_eq!(u8::from(&passive), 0b0000_0100);
    assert_eq!(u8::from(&ObjectFlags::default()), 0);

    // And the bits decode back to the same flags.
    for flags in [encrypted, signed, passive] {
        assert_eq!(ObjectFlags::from(u8::from(&flags)), flags);
    }
}

#[test]
fn chunk_flag_bits_match_the_specification() {
    // Header-layout.md, "Chunk Flags", in the order the table lists them.
    let bit = |apply: fn(&mut ChunkFlags)| {
        let mut flags = ChunkFlags::default();
        apply(&mut flags);
        flags.as_bytes()
    };
    assert_eq!(bit(|f| f.error = true), 1 << 0);
    assert_eq!(bit(|f| f.compression = true), 1 << 1);
    assert_eq!(bit(|f| f.same_bytes = true), 1 << 2);
    assert_eq!(bit(|f| f.duplicate = true), 1 << 3);
    assert_eq!(bit(|f| f.encryption = true), 1 << 4);
    assert_eq!(bit(|f| f.empty_file = true), 1 << 5);
    assert_eq!(bit(|f| f.virtual_chunk = true), 1 << 6);
}

#[test]
fn segment_header_layout_matches_the_specification() {
    // Header-layout.md, "Segment header", version 3:
    // magic(4) length(8) version(1) unique identifier(8) segment number(8)
    // chunkmap size(8) = 37 bytes.
    let encoded = SegmentHeader::new(0x5AFF, 1, 32768).encode_directly();

    assert_eq!(encoded.len(), 37);
    assert_eq!(&encoded[0..4], &0x7A66666Du32.to_be_bytes());
    assert_eq!(&encoded[4..12], &37u64.to_le_bytes());
    assert_eq!(encoded[12], 3, "segment header version");
    assert_eq!(&encoded[13..21], &0x5AFFu64.to_le_bytes());
    assert_eq!(&encoded[21..29], &1u64.to_le_bytes());
    assert_eq!(&encoded[29..37], &32768u64.to_le_bytes());
}

#[test]
fn compression_header_layout_matches_the_specification() {
    // Header-layout.md, "Compression header":
    // magic(4) length(8) version(1) algorithm(1) level(1) threshold(float32, 4).
    let encoded = CompressionHeader::new(CompressionAlgorithm::Zstd, 3, 1.05).encode_directly();

    assert_eq!(encoded.len(), 19);
    assert_eq!(&encoded[0..4], &0x7A666663u32.to_be_bytes());
    assert_eq!(&encoded[4..12], &19u64.to_le_bytes());
    assert_eq!(encoded[13], CompressionAlgorithm::Zstd as u8);
    assert_eq!(encoded[14], 3, "compression level");
    // Encoding.md gives 0x6666863f as the float32 encoding of 1.05.
    assert_eq!(&encoded[15..19], &[0x66, 0x66, 0x86, 0x3f]);
}

#[test]
fn chunk_header_layout_matches_the_specification() {
    // Header-layout.md, "Chunk Header", version 2:
    // magic(4) length(8) version(1) offset(8) size(8) flags(1) integrity hash(8).
    let flags = ChunkFlags {
        compression: true,
        ..Default::default()
    };
    let encoded = HeaderCoding::encode_directly(&ChunkHeader::new(0x1122, 0x3344, flags, 0x5566));

    assert_eq!(encoded.len(), 38);
    assert_eq!(&encoded[0..4], &0x7A666643u32.to_be_bytes());
    assert_eq!(&encoded[4..12], &38u64.to_le_bytes());
    assert_eq!(&encoded[13..21], &0x1122u64.to_le_bytes());
    assert_eq!(&encoded[21..29], &0x3344u64.to_le_bytes());
    assert_eq!(encoded[29], 1 << 1, "compression flag");
    assert_eq!(&encoded[30..38], &0x5566u64.to_le_bytes());

    // The chunk header map reserves exactly this size per entry.
    assert_eq!(
        ValueEncoder::encode_directly(&ChunkHeader::new(0, 0, ChunkFlags::default(), 0)).len(),
        38
    );
}

#[test]
fn hash_value_layout_matches_the_specification() {
    // Header-layout.md, "hash value structure":
    // magic(4) length(8) version(1) hash type(1) hash(bytes) [signature(64)].
    let mut hash_value = HashValue::new_empty(HashType::Blake3);
    hash_value.set_hash(vec![0xAB; 32]);
    let encoded = hash_value.encode_directly();

    assert_eq!(encoded.len(), 54);
    assert_eq!(&encoded[0..4], &0x7A666648u32.to_be_bytes());
    assert_eq!(&encoded[4..12], &54u64.to_le_bytes());
    assert_eq!(encoded[13], HashType::Blake3 as u8);
    assert_eq!(&encoded[14..22], &32u64.to_le_bytes(), "hash byte length");
    assert_eq!(&encoded[22..54], &[0xAB; 32]);

    // With a signature, the structure grows by exactly the 64 signature bytes.
    hash_value.set_ed25519_signature([0xCD; 64]);
    assert_eq!(hash_value.encode_directly().len(), 54 + 64);
}

#[test]
fn file_header_layout_matches_the_specification() {
    // Header-layout.md, "File header", unencrypted variant:
    // magic(4) length(8) version(1) file number(8) file type(1)
    // file name(PlatformString) parent file number(8) metadata map.
    let encoded = FileHeader::new(
        7,
        FileType::File,
        PlatformString::from(OsString::from("a")),
        3,
        HashMap::new(),
    )
    .encode_directly();

    assert_eq!(&encoded[0..4], &0x7A666666u32.to_be_bytes());
    assert_eq!(&encoded[4..12], &(encoded.len() as u64).to_le_bytes());
    assert_eq!(&encoded[13..21], &7u64.to_le_bytes(), "file number");
    assert_eq!(encoded[21], FileType::File as u8);
    // Encoding.md, PlatformString: encoding byte (unix = 0x00), length, bytes.
    assert_eq!(encoded[22], 0x00, "PlatformString unix encoding marker");
    assert_eq!(&encoded[23..31], &1u64.to_le_bytes());
    assert_eq!(encoded[31], b'a');
    assert_eq!(&encoded[32..40], &3u64.to_le_bytes(), "parent file number");
    assert_eq!(&encoded[40..48], &0u64.to_le_bytes(), "empty metadata map");
    assert_eq!(encoded.len(), 48);
}

#[test]
fn kdf_parameter_structures_match_the_specification() {
    let salt = [0u8; 32];

    // Header-layout.md, "KDF structure PBKDF2 / SHA256":
    // magic(4) length(8) iterations(uint32) salt(32). No version byte.
    let encoded = PBKDF2SHA256Parameters::new(1000, salt).encode_directly();
    assert_eq!(encoded.len(), 48);
    assert_eq!(&encoded[0..4], &0x6B646670u32.to_be_bytes());
    assert_eq!(&encoded[4..12], &48u64.to_le_bytes());
    assert_eq!(&encoded[12..16], &1000u32.to_le_bytes());
    assert_eq!(&encoded[16..48], &salt);

    // Header-layout.md, "KDF structure scrypt":
    // magic(4) length(8) log_n(uint8) r(uint32) p(uint32) salt(32).
    let encoded = ScryptParameters::new(2, 8, 1, salt).encode_directly();
    assert_eq!(encoded.len(), 53);
    assert_eq!(&encoded[0..4], &0x6B646673u32.to_be_bytes());
    assert_eq!(&encoded[4..12], &53u64.to_le_bytes());
    assert_eq!(encoded[12], 2, "log_n");
    assert_eq!(&encoded[13..17], &8u32.to_le_bytes(), "r");
    assert_eq!(&encoded[17..21], &1u32.to_le_bytes(), "p");
    assert_eq!(&encoded[21..53], &salt);
}

#[test]
fn argon2id_parameter_structure_stores_all_three_cost_parameters() {
    // Header-layout.md, "KDF structure argon2id":
    // magic(4) length(8) mem_cost(uint32) lanes(uint32) iterations(uint32)
    // salt(32) = 56 bytes. All three argon2id cost parameters (memory,
    // parallelism and time) have to be stored; without iterations the key
    // cannot be reproduced and the container would be undecryptable.
    let salt = [0u8; 32];
    let encoded = Argon2idParameters::new(8, 1, 3, salt).encode_directly();

    assert_eq!(encoded.len(), 56);
    assert_eq!(&encoded[0..4], &0x6B646661u32.to_be_bytes());
    assert_eq!(&encoded[4..12], &56u64.to_le_bytes());
    assert_eq!(&encoded[12..16], &8u32.to_le_bytes(), "mem_cost");
    assert_eq!(&encoded[16..20], &1u32.to_le_bytes(), "lanes");
    assert_eq!(&encoded[20..24], &3u32.to_le_bytes(), "iterations");
    assert_eq!(&encoded[24..56], &salt);
}

#[test]
fn maps_are_encoded_sorted_by_key() {
    // Footer-layout.md requires the offset maps to be "stored sorted by keys".
    // The in-memory type is a HashMap, so this has to be enforced on encoding.
    let mut footer = SegmentFooter::new_empty();
    for key in [9u64, 2, 7, 1, 5] {
        footer.object_header_offsets.insert(key, key * 10);
    }
    let encoded = footer.encode_directly();

    // Locate the map: version(1) + length_of_segment(8) follow the 12 byte
    // header prefix, then the object header offsets map begins.
    let map_start = 4 + 8 + 1 + 8;
    assert_eq!(&encoded[map_start..map_start + 8], &5u64.to_le_bytes());
    let mut offset = map_start + 8;
    for expected_key in [1u64, 2, 5, 7, 9] {
        assert_eq!(
            &encoded[offset..offset + 8],
            &expected_key.to_le_bytes(),
            "keys must be encoded in ascending order"
        );
        assert_eq!(
            &encoded[offset + 8..offset + 16],
            &(expected_key * 10).to_le_bytes()
        );
        offset += 16;
    }
}

#[test]
fn description_header_uses_the_specified_encoding_keys() {
    // Header-layout.md, "Description header hashmap".
    assert_eq!(ENCODING_KEY_CASE_NUMBER, "cn");
    assert_eq!(ENCODING_KEY_EVIDENCE_NUMBER, "ev");
    assert_eq!(ENCODING_KEY_EXAMINER_NAME, "ex");
    assert_eq!(ENCODING_KEY_NOTES, "no");
    assert_eq!(ENCODING_KEY_TOOL_NAME, "tn");
    assert_eq!(ENCODING_KEY_TOOL_VERSION, "tv");
    assert_eq!(ENCODING_KEY_LOGICAL_SECTOR_SIZE, "lss");
    assert_eq!(ENCODING_KEY_PHYSICAL_SECTOR_SIZE, "pss");
    assert_eq!(ENCODING_KEY_MODEL, "mdl");
    assert_eq!(ENCODING_KEY_SERIAL_NUMBER, "sn");
    assert_eq!(ENCODING_KEY_FIRMWARE, "fw");
    assert_eq!(ENCODING_KEY_MEDIA_TYPE, "mt");
    assert_eq!(ENCODING_KEY_INPUT_SOURCE, "is");
    assert_eq!(ENCODING_KEY_OPERATING_SYSTEM, "os");
    // Footer-layout.md, "Main footer": the description notes use "dn".
    assert_eq!(ENCODING_KEY_DESCRIPTION_NOTES, "dn");
}

#[test]
fn a_chunkmap_size_violating_the_specification_is_rejected() {
    // Header-layout.md, "Segment header": "Mandatory requirement: size % 16 = 0".
    let build = |chunkmap_size: u64| {
        let mut physical_objects = HashMap::new();
        physical_objects.insert(
            physical_object_header(
                64,
                CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
            ),
            Cursor::new(b"payload".to_vec()),
        );
        TestZffWriter::new(
            physical_objects,
            HashMap::new(),
            HashMap::new(),
            vec![HashType::Blake3],
            ZffCreationParameters {
                chunkmap_size: Some(chunkmap_size),
                ..default_creation_parameters()
            },
            ZffFilesOutput::Stream,
        )
    };

    for valid in [16u64, 32, 4096, DEFAULT_CHUNKMAP_SIZE] {
        assert!(build(valid).is_ok(), "{valid} is a valid chunkmap size");
    }
    for invalid in [1u64, 15, 1000, 32767] {
        assert!(
            build(invalid).is_err(),
            "{invalid} is not a multiple of 16 and has to be rejected"
        );
    }
}

#[test]
fn the_default_chunkmap_size_satisfies_the_specification() {
    assert_eq!(DEFAULT_CHUNKMAP_SIZE % CHUNKMAP_SIZE_ALIGNMENT, 0);
}

#[test]
fn tool_name_and_version_survive_a_description_header_roundtrip() {
    // The specification defines "tn" and "tv" as predefined description keys,
    // so the crate has to be able to write and read them.
    let mut description_header = DescriptionHeader::new_empty();
    description_header.set_tool_name("zffacquire");
    description_header.set_tool_version("3.0.0");
    description_header.set_examiner_name("tester");

    let decoded =
        DescriptionHeader::decode_directly(&mut Cursor::new(description_header.encode_directly()))
            .unwrap();

    assert_eq!(decoded.tool_name(), Some("zffacquire"));
    assert_eq!(decoded.tool_version(), Some("3.0.0"));
    assert_eq!(decoded.examiner_name(), Some("tester"));
    assert_eq!(decoded, description_header);
}

#[test]
fn tool_name_and_version_survive_a_container_roundtrip() {
    let mut object_header = physical_object_header(
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    object_header.description_header.set_tool_name("zffacquire");
    object_header.description_header.set_tool_version("3.0.0");
    let container = encode_physical_container(vec![(object_header, b"payload".repeat(16))]);

    let mut reader = initialized_reader(container);
    reader.set_active_object(1).unwrap();
    let description_header = &reader
        .active_object_header_ref()
        .unwrap()
        .description_header;

    assert_eq!(description_header.tool_name(), Some("zffacquire"));
    assert_eq!(description_header.tool_version(), Some("3.0.0"));
}

// ---------------------------------------------------------------------------
// Logical acquisition from the filesystem
// ---------------------------------------------------------------------------
//
// The logical object tests above use an in-memory source. Real acquisitions go
// through [LogicalObjectSourceFilesystem], which walks the filesystem and
// resolves directories, symlinks, hardlinks and metadata. These tests exercise
// that path against a real temporary directory tree.

/// Encodes the given filesystem paths into a logical container.
fn encode_filesystem_container(paths: Vec<PathBuf>, chunk_size: u64) -> Vec<u8> {
    let source = LogicalObjectSourceFilesystem::new(paths).unwrap();
    let mut logical_objects: HashMap<ObjectHeader, Box<dyn LogicalObjectSource>> = HashMap::new();
    logical_objects.insert(logical_object_header(1, chunk_size), Box::new(source));

    let mut writer: TestZffWriter = ZffWriter::new(
        HashMap::new(),
        logical_objects,
        HashMap::new(),
        vec![HashType::Blake3],
        default_creation_parameters(),
        ZffFilesOutput::Stream,
    )
    .unwrap();
    let mut container = Vec::new();
    writer.read_to_end(&mut container).unwrap();
    container
}

/// Maps the file names of a logical object to their file numbers.
fn file_numbers_by_name(reader: &mut ZffReader<Mutex<Cursor<Vec<u8>>>>) -> HashMap<String, u64> {
    let mut by_name = HashMap::new();
    // File numbers are assigned sequentially starting at 1.
    for file_number in 1..=64u64 {
        if reader.set_active_file(file_number).is_err() {
            continue;
        }
        let header = reader.current_fileheader().unwrap();
        by_name.insert(header.filename.to_string_lossy(), file_number);
    }
    by_name
}

#[test]
fn filesystem_acquisition_preserves_file_contents() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("first.txt"), b"first file contents").unwrap();
    std::fs::write(dir.path().join("second.bin"), vec![0xAB; 300]).unwrap();
    std::fs::write(dir.path().join("empty.txt"), b"").unwrap();

    let container = encode_filesystem_container(vec![dir.path().to_path_buf()], 64);
    let mut reader = initialized_reader(container);
    reader.set_active_object(1).unwrap();
    let by_name = file_numbers_by_name(&mut reader);

    for (name, expected) in [
        ("first.txt", b"first file contents".to_vec()),
        ("second.bin", vec![0xAB; 300]),
        ("empty.txt", Vec::new()),
    ] {
        let file_number = by_name
            .get(name)
            .unwrap_or_else(|| panic!("{name} is missing from the container: {by_name:?}"));
        reader.set_active_file(*file_number).unwrap();
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        assert_eq!(output, expected, "contents of {name}");
    }
}

#[test]
fn filesystem_acquisition_preserves_a_nested_directory_tree() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("outer").join("inner");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("deep.txt"), b"deeply nested").unwrap();
    std::fs::write(dir.path().join("outer").join("mid.txt"), b"mid level").unwrap();

    let container = encode_filesystem_container(vec![dir.path().to_path_buf()], 64);
    let mut reader = initialized_reader(container);
    reader.set_active_object(1).unwrap();
    let by_name = file_numbers_by_name(&mut reader);

    for name in ["outer", "inner", "deep.txt", "mid.txt"] {
        assert!(by_name.contains_key(name), "{name} missing: {by_name:?}");
    }

    // The parent chain has to survive: deep.txt -> inner -> outer.
    reader.set_active_file(by_name["deep.txt"]).unwrap();
    let deep_parent = reader.current_fileheader().unwrap().parent_file_number;
    assert_eq!(deep_parent, by_name["inner"]);

    reader.set_active_file(by_name["inner"]).unwrap();
    let inner_header = reader.current_fileheader().unwrap();
    assert_eq!(inner_header.file_type, FileType::Directory);
    assert_eq!(inner_header.parent_file_number, by_name["outer"]);

    reader.set_active_file(by_name["deep.txt"]).unwrap();
    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();
    assert_eq!(output, b"deeply nested");
}

#[test]
fn filesystem_acquisition_records_file_types() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("a_directory")).unwrap();
    std::fs::write(dir.path().join("a_file.txt"), b"regular").unwrap();

    let container = encode_filesystem_container(vec![dir.path().to_path_buf()], 64);
    let mut reader = initialized_reader(container);
    reader.set_active_object(1).unwrap();
    let by_name = file_numbers_by_name(&mut reader);

    reader.set_active_file(by_name["a_directory"]).unwrap();
    assert_eq!(
        reader.current_fileheader().unwrap().file_type,
        FileType::Directory
    );

    reader.set_active_file(by_name["a_file.txt"]).unwrap();
    assert_eq!(
        reader.current_fileheader().unwrap().file_type,
        FileType::File
    );
}

#[test]
fn filesystem_acquisition_handles_a_file_larger_than_one_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let contents: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.path().join("large.bin"), &contents).unwrap();

    let container = encode_filesystem_container(vec![dir.path().to_path_buf()], 64);
    let mut reader = initialized_reader(container);
    reader.set_active_object(1).unwrap();
    let by_name = file_numbers_by_name(&mut reader);

    reader.set_active_file(by_name["large.bin"]).unwrap();
    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();

    assert_eq!(output, contents);
}

#[cfg(target_family = "unix")]
#[test]
fn filesystem_acquisition_preserves_a_symlink_target() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("target.txt"), b"link target").unwrap();
    std::os::unix::fs::symlink(dir.path().join("target.txt"), dir.path().join("link.txt")).unwrap();

    let container = encode_filesystem_container(vec![dir.path().to_path_buf()], 64);
    let mut reader = initialized_reader(container);
    reader.set_active_object(1).unwrap();
    let by_name = file_numbers_by_name(&mut reader);

    reader.set_active_file(by_name["link.txt"]).unwrap();
    let header = reader.current_fileheader().unwrap();
    assert_eq!(header.file_type, FileType::Symlink);

    // The target is stored as the file's data, encoded as a PlatformString, so
    // that the exact bytes of the original path are preserved.
    let mut encoded_target = Vec::new();
    reader.read_to_end(&mut encoded_target).unwrap();
    let target = PlatformString::decode_directly(&mut Cursor::new(encoded_target)).unwrap();

    assert_eq!(
        target,
        PlatformString::from(dir.path().join("target.txt").into_os_string())
    );
}

#[cfg(target_family = "unix")]
#[test]
fn filesystem_acquisition_preserves_unix_metadata() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("perm.txt");
    std::fs::write(&path, b"metadata carrier").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

    let container = encode_filesystem_container(vec![dir.path().to_path_buf()], 64);
    let mut reader = initialized_reader(container);
    reader.set_active_object(1).unwrap();
    let by_name = file_numbers_by_name(&mut reader);

    reader.set_active_file(by_name["perm.txt"]).unwrap();
    let header = reader.current_fileheader().unwrap();

    // The specification predefines these metadata extension keys.
    for key in ["uid", "gid", "mode", "mtime", "atime"] {
        assert!(
            header.metadata_ext.contains_key(key),
            "metadata key {key} is missing: {:?}",
            header.metadata_ext.keys().collect::<Vec<_>>()
        );
    }
    match header.metadata_ext.get("mode") {
        Some(MetadataExtendedValue::U32(mode)) => {
            assert_eq!(mode & 0o777, 0o640, "permission bits");
        }
        other => panic!("expected mode to be stored as an u32, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// On-disk containers
// ---------------------------------------------------------------------------
//
// Every test above writes to [ZffFilesOutput::Stream]. Real acquisitions use
// [ZffFilesOutput::NewContainer], which writes numbered segment files through
// [ZffWriter::generate_files], and [ZffFilesOutput::ExtendContainer], which
// appends further objects to an existing container.

/// Opens a set of segment files as a reader over the container.
fn reader_over_files(paths: &[PathBuf]) -> ZffReader<Mutex<File>> {
    let readers = paths
        .iter()
        .map(|path| Mutex::new(File::open(path).unwrap()))
        .collect();
    let mut reader = ZffReader::with_reader(readers).unwrap();
    reader.initialize_objects_all().unwrap();
    reader
}

/// Writes the given physical objects to segment files below `prefix`.
fn generate_container_files(
    objects: Vec<(ObjectHeader, Vec<u8>)>,
    prefix: PathBuf,
    target_segment_size: Option<u64>,
) -> Vec<PathBuf> {
    let mut physical_objects = HashMap::new();
    for (object_header, input) in objects {
        physical_objects.insert(object_header, Cursor::new(input));
    }
    let params = ZffCreationParameters {
        target_segment_size,
        ..default_creation_parameters()
    };
    let mut writer: TestZffWriter = ZffWriter::new(
        physical_objects,
        HashMap::new(),
        HashMap::new(),
        vec![HashType::Blake3],
        params,
        ZffFilesOutput::NewContainer(prefix),
    )
    .unwrap();
    writer.generate_files().unwrap()
}

#[test]
fn generate_files_writes_a_single_readable_segment_file() {
    let dir = tempfile::tempdir().unwrap();
    let input = b"on-disk container payload ".repeat(32);
    let object_header = physical_object_header(
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );

    let files = generate_container_files(
        vec![(object_header, input.clone())],
        dir.path().join("container"),
        None,
    );

    assert_eq!(files.len(), 1);
    assert_eq!(
        files[0].extension().and_then(|e| e.to_str()),
        Some("z01"),
        "the first segment file has to use the .z01 extension"
    );
    assert!(files[0].is_file());

    let mut reader = reader_over_files(&files);
    reader.set_active_object(1).unwrap();
    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();
    assert_eq!(output, input);
}

#[test]
fn generate_files_splits_into_numbered_segment_files() {
    let dir = tempfile::tempdir().unwrap();
    let input: Vec<u8> = (0..32768u32).map(|i| (i % 251) as u8).collect();
    let object_header = physical_object_header(
        128,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let target_segment_size = 4096;

    let files = generate_container_files(
        vec![(object_header, input.clone())],
        dir.path().join("container"),
        Some(target_segment_size),
    );

    assert!(files.len() > 2, "expected several segments, got {files:?}");
    // Extensions have to run z01, z02, z03, ... in order.
    for (index, path) in files.iter().enumerate() {
        assert_eq!(
            path.extension().and_then(|e| e.to_str()),
            Some(format!("z{:02}", index + 1).as_str()),
            "unexpected extension for segment {index}"
        );
        assert!(path.is_file(), "{path:?} was reported but not written");
        // The size cap has to hold for files on disk, not only for streams.
        let written = std::fs::metadata(path).unwrap().len();
        assert!(
            written <= target_segment_size,
            "segment {index} is {written} bytes, target was {target_segment_size}"
        );
    }

    let mut reader = reader_over_files(&files);
    reader.set_active_object(1).unwrap();
    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();
    assert_eq!(output, input);
}

#[test]
fn generate_files_rolls_the_extension_past_z09() {
    // file_extension_next_value switches format after z09, which only shows up
    // once a container needs more than nine segments.
    let dir = tempfile::tempdir().unwrap();
    let input: Vec<u8> = (0..32768u32).map(|i| (i % 251) as u8).collect();
    let object_header = physical_object_header(
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );

    let files = generate_container_files(
        vec![(object_header, input.clone())],
        dir.path().join("container"),
        Some(2048),
    );

    assert!(
        files.len() > 10,
        "expected more than ten segments to exercise the rollover, got {}",
        files.len()
    );
    assert_eq!(files[8].extension().and_then(|e| e.to_str()), Some("z09"));
    assert_eq!(files[9].extension().and_then(|e| e.to_str()), Some("z10"));

    let mut reader = reader_over_files(&files);
    reader.set_active_object(1).unwrap();
    let mut output = Vec::new();
    reader.read_to_end(&mut output).unwrap();
    assert_eq!(output, input);
}

#[test]
fn generate_files_is_rejected_for_a_stream_output() {
    let mut physical_objects = HashMap::new();
    physical_objects.insert(
        physical_object_header(
            64,
            CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
        ),
        Cursor::new(b"payload".to_vec()),
    );
    let mut writer: TestZffWriter = ZffWriter::new(
        physical_objects,
        HashMap::new(),
        HashMap::new(),
        vec![HashType::Blake3],
        default_creation_parameters(),
        ZffFilesOutput::Stream,
    )
    .unwrap();

    assert!(writer.generate_files().is_err());
}

/// Appends a further physical object to the container made of `existing_files`.
fn extend_container_files(
    existing_files: Vec<PathBuf>,
    object_input: Vec<u8>,
    chunk_size: u64,
) -> Vec<PathBuf> {
    // The object number is assigned by the writer, continuing the existing
    // container, so the number given here is not the one that ends up stored.
    let mut physical_objects = HashMap::new();
    physical_objects.insert(
        physical_object_header_with_number(
            1,
            chunk_size,
            CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
        ),
        Cursor::new(object_input),
    );
    let mut writer: TestZffWriter = ZffWriter::new(
        physical_objects,
        HashMap::new(),
        HashMap::new(),
        vec![HashType::Blake3],
        default_creation_parameters(),
        ZffFilesOutput::ExtendContainer(existing_files),
    )
    .unwrap();
    writer.generate_files().unwrap()
}

#[test]
fn an_existing_container_can_be_extended_with_another_object() {
    let dir = tempfile::tempdir().unwrap();
    let first_input = b"the originally acquired object ".repeat(16);
    let second_input = b"the appended object ".repeat(16);

    let created = generate_container_files(
        vec![(
            physical_object_header(
                64,
                CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
            ),
            first_input.clone(),
        )],
        dir.path().join("container"),
        None,
    );
    let appended = extend_container_files(created.clone(), second_input.clone(), 64);

    // Reading the container has to expose both objects.
    let mut all_files = created;
    for path in appended {
        if !all_files.contains(&path) {
            all_files.push(path);
        }
    }
    let mut reader = reader_over_files(&all_files);
    let objects = reader.list_objects().unwrap();
    assert_eq!(objects.len(), 2, "expected two objects, got {objects:?}");

    let mut outputs = Vec::new();
    for object_number in objects.keys() {
        reader.set_active_object(*object_number).unwrap();
        let mut output = Vec::new();
        reader.read_to_end(&mut output).unwrap();
        outputs.push(output);
    }

    assert!(
        outputs.contains(&first_input),
        "the original object is no longer readable after extending"
    );
    assert!(
        outputs.contains(&second_input),
        "the appended object is not readable"
    );
}

#[test]
fn extending_a_container_assigns_the_next_object_number() {
    let dir = tempfile::tempdir().unwrap();
    let created = generate_container_files(
        vec![(
            physical_object_header(
                64,
                CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
            ),
            b"first".repeat(16),
        )],
        dir.path().join("container"),
        None,
    );

    let appended = extend_container_files(created.clone(), b"second".repeat(16), 64);

    let mut all_files = created;
    for path in appended {
        if !all_files.contains(&path) {
            all_files.push(path);
        }
    }
    let reader = reader_over_files(&all_files);
    let objects = reader.list_objects().unwrap();

    // The original object keeps number 1, the appended one continues at 2.
    assert_eq!(
        objects.keys().copied().collect::<Vec<_>>(),
        vec![1, 2],
        "object numbers have to continue the existing container"
    );
}

#[test]
fn extending_a_non_container_file_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let bogus = dir.path().join("not-a-container.z01");
    std::fs::write(&bogus, b"this is not a zff container").unwrap();

    let mut physical_objects = HashMap::new();
    physical_objects.insert(
        physical_object_header(
            64,
            CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
        ),
        Cursor::new(b"payload".to_vec()),
    );
    let result: Result<TestZffWriter> = ZffWriter::new(
        physical_objects,
        HashMap::new(),
        HashMap::new(),
        vec![HashType::Blake3],
        default_creation_parameters(),
        ZffFilesOutput::ExtendContainer(vec![bogus]),
    );

    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Decoder robustness
// ---------------------------------------------------------------------------
//
// A forensic container is untrusted input: it may be corrupt, truncated, or
// deliberately malformed. The decoders must reject such input with an error
// rather than panicking, over-allocating, or looping.
//
// These tests use a fixed seed so a failure is reproducible; the `fuzz`
// directory holds the matching cargo-fuzz targets for unbounded exploration.

/// A small deterministic PRNG, so a failing case can always be reproduced.
struct Xorshift64(u64);

impl Xorshift64 {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn next_usize(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next_u64() % bound as u64) as usize
    }
}

/// Runs every header and footer decoder over the given bytes. None of them may
/// panic; returning an error is the expected outcome for malformed input.
fn decode_with_every_decoder(bytes: &[u8]) {
    macro_rules! try_decode {
        ($($ty:ty),* $(,)?) => {
            $(
                let _ = <$ty>::decode_directly(&mut Cursor::new(bytes));
            )*
        };
    }
    try_decode!(
        SegmentHeader,
        ObjectHeader,
        FileHeader,
        CompressionHeader,
        DescriptionHeader,
        EncryptionHeader,
        PBEHeader,
        HashHeader,
        SegmentFooter,
        MainFooter,
        ObjectFooterPhysical,
        ObjectFooterLogical,
        ObjectFooterVirtual,
        FileFooter,
    );
    let _ = <ChunkHeader as HeaderCoding>::decode_directly(&mut Cursor::new(bytes));
}

#[test]
fn decoders_reject_random_bytes_without_panicking() {
    let mut rng = Xorshift64(0x5AFF_0001);
    for _ in 0..2048 {
        let len = rng.next_usize(160);
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
        decode_with_every_decoder(&bytes);
    }
}

#[test]
fn decoders_reject_random_bytes_behind_a_valid_identifier() {
    // Random bytes almost never carry a valid magic number, so the decoders
    // would bail out immediately. Prefixing a real identifier drives the input
    // deeper into each decoder, where the length and content parsing happens.
    let mut rng = Xorshift64(0x5AFF_0002);
    let identifiers = [
        HEADER_IDENTIFIER_SEGMENT_HEADER,
        HEADER_IDENTIFIER_OBJECT_HEADER,
        HEADER_IDENTIFIER_FILE_HEADER,
        HEADER_IDENTIFIER_COMPRESSION_HEADER,
        HEADER_IDENTIFIER_DESCRIPTION_HEADER,
        HEADER_IDENTIFIER_ENCRYPTION_HEADER,
        HEADER_IDENTIFIER_PBE_HEADER,
        HEADER_IDENTIFIER_HASH_HEADER,
        HEADER_IDENTIFIER_CHUNK_HEADER,
    ];

    for identifier in identifiers {
        for _ in 0..512 {
            let mut bytes = identifier.to_be_bytes().to_vec();
            // A plausible length field, sometimes wildly wrong on purpose.
            let declared_length = match rng.next_usize(4) {
                0 => rng.next_u64(),
                1 => u64::MAX,
                2 => 0,
                _ => rng.next_usize(128) as u64,
            };
            bytes.extend_from_slice(&declared_length.to_le_bytes());
            let payload_len = rng.next_usize(128);
            bytes.extend((0..payload_len).map(|_| rng.next_u64() as u8));
            decode_with_every_decoder(&bytes);
        }
    }
}

#[test]
fn a_reader_over_mutated_containers_never_panics() {
    // Single-byte mutations of a real container: the reader has to fail
    // cleanly, whatever the mutation hits.
    let input = b"mutation resistance payload ".repeat(24);
    let object_header = physical_object_header(
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let original = encode_physical_container(vec![(object_header, input)]);

    let mut rng = Xorshift64(0x5AFF_0003);
    for _ in 0..768 {
        let mut mutated = original.clone();
        // Between one and three flipped bytes per iteration.
        for _ in 0..=rng.next_usize(3) {
            let index = rng.next_usize(mutated.len());
            mutated[index] ^= 1 << rng.next_usize(8);
        }

        let Ok(mut reader) = ZffReader::with_reader(vec![Mutex::new(Cursor::new(mutated))]) else {
            continue;
        };
        let Ok(objects) = reader.list_objects() else {
            continue;
        };
        for object_number in objects.keys().copied().collect::<Vec<_>>() {
            if reader.initialize_object(object_number).is_err() {
                continue;
            }
            if reader.set_active_object(object_number).is_err() {
                continue;
            }
            // Bounded: a corrupted length field must not make this read forever.
            let mut output = Vec::new();
            let _ = std::io::Read::by_ref(&mut reader)
                .take(1 << 20)
                .read_to_end(&mut output);
        }
    }
}

#[test]
fn a_reader_over_truncated_containers_never_panics() {
    let input = b"truncation resistance payload ".repeat(24);
    let object_header = physical_object_header(
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let original = encode_physical_container(vec![(object_header, input)]);

    // Every truncation length, not a sample: this is cheap and exhaustive.
    for length in 0..original.len() {
        let truncated = original[..length].to_vec();
        let Ok(mut reader) = ZffReader::with_reader(vec![Mutex::new(Cursor::new(truncated))])
        else {
            continue;
        };
        if reader.initialize_objects_all().is_err() {
            continue;
        }
        if reader.set_active_object(1).is_err() {
            continue;
        }
        let mut output = Vec::new();
        let _ = std::io::Read::by_ref(&mut reader)
            .take(1 << 20)
            .read_to_end(&mut output);
    }
}

#[test]
fn every_single_bit_mutation_of_a_container_is_handled_cleanly() {
    // Exhaustive rather than sampled: every bit of a real container is flipped
    // in turn. This is the test that caught an unbounded allocation driven by a
    // corrupted length field, where a single flipped bit made the reader try to
    // allocate 2^60 bytes and abort the process.
    let input = b"mutation resistance payload ".repeat(8);
    let object_header = physical_object_header(
        64,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
    );
    let original = encode_physical_container(vec![(object_header, input)]);

    for index in 0..original.len() {
        for bit in 0..8 {
            let mut mutated = original.clone();
            mutated[index] ^= 1 << bit;

            let Ok(mut reader) = ZffReader::with_reader(vec![Mutex::new(Cursor::new(mutated))])
            else {
                continue;
            };
            if reader.initialize_objects_all().is_err() || reader.set_active_object(1).is_err() {
                continue;
            }
            let mut output = Vec::new();
            let _ = std::io::Read::by_ref(&mut reader)
                .take(1 << 20)
                .read_to_end(&mut output);
        }
    }
}
