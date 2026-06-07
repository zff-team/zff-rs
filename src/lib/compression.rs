//! Module for compression operations in zff.
//!
//! This module provides compression and decompression functionality for zff containers,
//! supporting multiple compression algorithms to optimize storage efficiency.
//!
//! # Types
//!
//! - [`CompressionAlgorithm`]: Enum defining all supported compression algorithms (None, Zstd, Lz4)
//!
//! # Functions
//!
//! - [`decompress_buffer`]: Decompresses a buffer with the given algorithm
//! - [`decompress_reader`]: Returns a reader that decompresses data on-the-fly
//!
//! # Features
//!
//! - Support for Zstd and LZ4 compression algorithms
//! - Configurable compression levels and thresholds
//! - Streaming decompression support

// - STD
use std::borrow::Borrow;
use std::fmt;
use std::io::Read;

// - internal
use crate::Result;

// - external
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Defines all compression algorithms, which are implemented in zff.
///
/// # Example
/// ```
/// use zff::CompressionAlgorithm;
///
/// // Convert from string
/// let algorithm = CompressionAlgorithm::from("zstd");
/// assert!(matches!(algorithm, CompressionAlgorithm::Zstd));
///
/// // All variants
/// let none = CompressionAlgorithm::None;
/// let zstd = CompressionAlgorithm::Zstd;
/// let lz4 = CompressionAlgorithm::Lz4;
/// ```
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum CompressionAlgorithm {
    /// No compression - encoded as 0 in the header.
    None = 0,
    /// Zstd compression (default) - encoded as 1 in the header.
    Zstd = 1,
    /// LZ4 compression - encoded as 2 in the header. LZ4 frame format is used (not the LZ4 block format) for compression.
    Lz4 = 2,
}

impl From<&str> for CompressionAlgorithm {
    fn from(algorithm: &str) -> CompressionAlgorithm {
        let algorithm = algorithm.to_lowercase();
        match algorithm.as_str() {
            "zstd" => CompressionAlgorithm::Zstd,
            "lz4" => CompressionAlgorithm::Lz4,
            _ => CompressionAlgorithm::None,
        }
    }
}

impl fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let value = match self {
            CompressionAlgorithm::Zstd => "Zstd",
            CompressionAlgorithm::Lz4 => "Lz4",
            CompressionAlgorithm::None => "None",
        };
        write!(f, "{value}")
    }
}

/// Decompresses a buffer with the given [CompressionAlgorithm].
///
/// # Example
/// ```
/// use zff::{CompressionAlgorithm, decompress_buffer};
///
/// // Decompress uncompressed data
/// let uncompressed_data = b"Hello, World!";
/// let decompressed = decompress_buffer(uncompressed_data, CompressionAlgorithm::None).unwrap();
/// assert_eq!(decompressed, uncompressed_data);
///
/// // Note: To decompress Zstd or Lz4 data, you need to provide actual compressed data
/// // This example shows the function signature for those cases:
/// // let compressed_zstd_data: &[u8] = ...;
/// // let decompressed = decompress_buffer(compressed_zstd_data, CompressionAlgorithm::Zstd)?;
/// ```
pub fn decompress_buffer<C>(buffer: &[u8], compression_algorithm: C) -> Result<Vec<u8>>
where
    C: Borrow<CompressionAlgorithm>,
{
    match compression_algorithm.borrow() {
        CompressionAlgorithm::None => Ok(buffer.to_vec()),
        CompressionAlgorithm::Zstd => {
            let mut decompressed_buffer = Vec::new();
            let mut decoder = zstd::stream::read::Decoder::new(buffer)?;
            decoder.read_to_end(&mut decompressed_buffer)?;
            Ok(decompressed_buffer)
        }
        CompressionAlgorithm::Lz4 => {
            let mut decompressed_buffer = Vec::new();
            let mut decompressor = lz4_flex::frame::FrameDecoder::new(buffer);
            decompressor.read_to_end(&mut decompressed_buffer)?;
            Ok(decompressed_buffer)
        }
    }
}

/// Decompresses a reader with the given [CompressionAlgorithm].
///
/// Returns a boxed reader that decompresses data on-the-fly as it is read.
///
/// # Example
/// ```
/// use zff::{CompressionAlgorithm, decompress_reader};
/// use std::io::Cursor;
///
/// // Create a reader for uncompressed data
/// let uncompressed_data = b"Hello, World!";
/// let mut cursor = Cursor::new(uncompressed_data);
/// let mut reader = decompress_reader(&mut cursor, CompressionAlgorithm::None).unwrap();
///
/// let mut buf = Vec::new();
/// reader.read_to_end(&mut buf).unwrap();
/// assert_eq!(buf, uncompressed_data);
///
/// // Note: For Zstd or Lz4, you would use actual compressed data:
/// // let compressed_data: Vec<u8> = ...;
/// // let mut cursor = Cursor::new(compressed_data);
/// // let mut reader = decompress_reader(&mut cursor, CompressionAlgorithm::Zstd)?;
/// ```
pub fn decompress_reader<C, R>(
    input: &mut R,
    compression_algorithm: C,
) -> Result<Box<dyn Read + Send + '_>>
where
    C: Borrow<CompressionAlgorithm>,
    R: Read + std::marker::Send + 'static,
{
    match compression_algorithm.borrow() {
        CompressionAlgorithm::None => Ok(Box::new(input)),
        CompressionAlgorithm::Zstd => {
            let decoder = zstd::stream::read::Decoder::new(input)?;
            Ok(Box::new(decoder))
        }
        CompressionAlgorithm::Lz4 => {
            let decompressor = lz4_flex::frame::FrameDecoder::new(input);
            Ok(Box::new(decompressor))
        }
    }
}
