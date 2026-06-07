use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::Mutex;

use crate::io::{
    ZffCreationParameters, compress_buffer,
    zffreader::{ObjectType as ReaderObjectType, ZffReader},
    zffwriter::{ZffFilesOutput, ZffWriter},
};
use crate::prelude::*;
use crate::{HashType, decompress_buffer};

fn physical_object_header(chunk_size: u64, compression_header: CompressionHeader) -> ObjectHeader {
    ObjectHeader::new(
        1,
        None,
        chunk_size,
        compression_header,
        DescriptionHeader::new_empty(),
        ObjectType::Physical,
        ObjectFlags::default(),
    )
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
    let mut physical_objects = HashMap::new();
    physical_objects.insert(object_header, Cursor::new(input.clone()));

    let mut writer: ZffWriter<Cursor<Vec<u8>>, Mutex<Cursor<Vec<u8>>>> = ZffWriter::new(
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
fn tiny_input_is_rejected_as_container() {
    let input = Mutex::new(Cursor::new(vec![0_u8; 7]));

    let result = ZffReader::with_reader(vec![input]);

    assert!(result.is_err());
}
