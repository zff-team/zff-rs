//! Throughput benchmarks for the container write and read paths.
//!
//! These cover the hot loops: the per-chunk work in the writer (chunking,
//! hashing, the segment size accounting and deduplication) and the per-chunk
//! work in the reader. They exist so a change to those loops can be measured
//! rather than guessed at.

use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::Mutex;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use zff::HashType;
use zff::header::*;
use zff::io::ZffCreationParameters;
use zff::io::zffreader::ZffReader;
use zff::io::zffwriter::{SegmentationState, ZffFilesOutput, ZffWriter};
use zff::prelude::*;

const PAYLOAD_SIZE: usize = 4 * 1024 * 1024;
const CHUNK_SIZE: u64 = 32768;

fn object_header(compression: CompressionHeader) -> ObjectHeader {
    ObjectHeader::new(
        1,
        None,
        CHUNK_SIZE,
        compression,
        DescriptionHeader::new_empty(),
        ObjectType::Physical,
        ObjectFlags::default(),
    )
}

fn creation_parameters() -> ZffCreationParameters<Mutex<Cursor<Vec<u8>>>> {
    ZffCreationParameters {
        unique_identifier: 0x5A_FF,
        ..Default::default()
    }
}

/// Data that does not compress or deduplicate, so the benchmark measures the
/// pipeline rather than the shortcuts.
fn incompressible_payload() -> Vec<u8> {
    let mut state = 0x243F_6A88_85A3_08D3u64;
    (0..PAYLOAD_SIZE)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn write_container(
    payload: &[u8],
    compression: CompressionHeader,
    params: ZffCreationParameters<Mutex<Cursor<Vec<u8>>>>,
) -> Vec<u8> {
    let mut physical_objects = HashMap::new();
    physical_objects.insert(object_header(compression), Cursor::new(payload.to_vec()));
    let mut writer: ZffWriter<Cursor<Vec<u8>>, Mutex<Cursor<Vec<u8>>>> = ZffWriter::new(
        physical_objects,
        HashMap::new(),
        HashMap::new(),
        vec![HashType::Blake3],
        params,
        ZffFilesOutput::Stream,
    )
    .unwrap();
    let mut container = Vec::new();
    writer.read_to_end(&mut container).unwrap();
    container
}

/// Writes the whole payload across segments.
///
/// In stream mode a read ends when the current segment is finished, so the
/// writer has to be advanced explicitly; otherwise only the first segment is
/// produced and the benchmark would measure a fraction of the payload.
fn write_segmented_container(payload: &[u8], target_segment_size: u64) -> usize {
    let mut physical_objects = HashMap::new();
    physical_objects.insert(
        object_header(CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0)),
        Cursor::new(payload.to_vec()),
    );
    let mut writer: ZffWriter<Cursor<Vec<u8>>, Mutex<Cursor<Vec<u8>>>> = ZffWriter::new(
        physical_objects,
        HashMap::new(),
        HashMap::new(),
        vec![HashType::Blake3],
        ZffCreationParameters {
            target_segment_size: Some(target_segment_size),
            ..creation_parameters()
        },
        ZffFilesOutput::Stream,
    )
    .unwrap();

    let mut total = 0;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        loop {
            match writer.read(&mut buffer).unwrap() {
                0 => break,
                n => total += n,
            }
        }
        match writer.next_segment() {
            SegmentationState::LastSegmentFinished => break,
            SegmentationState::SegmentFinished => (),
            SegmentationState::SegmentNotFinished => {
                panic!("the writer reported an unfinished segment after a complete read")
            }
        }
    }
    total
}

fn bench_write(c: &mut Criterion) {
    let payload = incompressible_payload();
    let mut group = c.benchmark_group("write");
    group.throughput(Throughput::Bytes(payload.len() as u64));

    group.bench_function("uncompressed", |b| {
        b.iter(|| {
            write_container(
                &payload,
                CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
                creation_parameters(),
            )
        })
    });

    group.bench_function("zstd", |b| {
        b.iter(|| {
            write_container(
                &payload,
                CompressionHeader::new(CompressionAlgorithm::Zstd, 3, 1.01),
                creation_parameters(),
            )
        })
    });

    // Segmentation runs the per-chunk size accounting on every chunk.
    for target_segment_size in [256 * 1024u64, 1024 * 1024] {
        group.bench_with_input(
            BenchmarkId::new("segmented", target_segment_size),
            &target_segment_size,
            |b, &target_segment_size| {
                b.iter(|| write_segmented_container(&payload, target_segment_size))
            },
        );
    }

    group.finish();
}

fn bench_deduplication(c: &mut Criterion) {
    // Repeating chunks, so deduplication actually has work to do.
    let block: Vec<u8> = incompressible_payload()
        .into_iter()
        .take(CHUNK_SIZE as usize * 8)
        .collect();
    let payload: Vec<u8> = block.iter().copied().cycle().take(PAYLOAD_SIZE).collect();

    let mut group = c.benchmark_group("deduplication");
    group.throughput(Throughput::Bytes(payload.len() as u64));

    // Note: the "disabled" arm measures the same path as write/uncompressed and
    // matches it (~1.7 ms) when this group is run on its own, but reads roughly
    // three times slower when the whole suite runs in one process. Compare the
    // two arms of this group against each other, and use `cargo bench --bench
    // container -- deduplication` before concluding anything from a change here.
    group.bench_function("disabled", |b| {
        b.iter(|| {
            write_container(
                &payload,
                CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
                creation_parameters(),
            )
        })
    });

    group.bench_function("enabled", |b| {
        b.iter(|| {
            write_container(
                &payload,
                CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
                ZffCreationParameters {
                    deduplication_metadata: Some(DeduplicationMetadata {
                        deduplication_map: DeduplicationChunkMap::new_in_memory_map(),
                        original_zffreader: None,
                    }),
                    ..creation_parameters()
                },
            )
        })
    });

    group.finish();
}

fn bench_read(c: &mut Criterion) {
    let payload = incompressible_payload();
    let container = write_container(
        &payload,
        CompressionHeader::new(CompressionAlgorithm::None, 0, 1.0),
        creation_parameters(),
    );

    let mut group = c.benchmark_group("read");
    group.throughput(Throughput::Bytes(payload.len() as u64));

    group.bench_function("sequential", |b| {
        b.iter(|| {
            let mut reader =
                ZffReader::with_reader(vec![Mutex::new(Cursor::new(container.clone()))]).unwrap();
            reader.initialize_objects_all().unwrap();
            reader.set_active_object(1).unwrap();
            let mut output = Vec::new();
            reader.read_to_end(&mut output).unwrap();
            output
        })
    });

    group.finish();
}

criterion_group!(benches, bench_write, bench_deduplication, bench_read);
criterion_main!(benches);
