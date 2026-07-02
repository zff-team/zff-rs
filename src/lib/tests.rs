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
