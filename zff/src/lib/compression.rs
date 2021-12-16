// - external
use serde::{Serialize};

/// Defines all compression algorithms, which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Serialize)]
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
			"none" | _ => CompressionAlgorithm::None,
		}
	}
}
