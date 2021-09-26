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
}