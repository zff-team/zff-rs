//! Prelude module for convenient access to commonly used types and traits.
//!
//! This module re-exports the most frequently used types, traits, and constants
//! from the zff crate, allowing for more concise imports in user code.
//!
//! # Example
//!
//! Instead of importing many items individually:
//! ```no_run
//! use zff::header::ObjectHeader;
//! use zff::footer::MainFooter;
//! use zff::CompressionAlgorithm;
//! use zff::HashType;
//! ```
//!
//! You can use the prelude:
//! ```no_run
//! use zff::prelude::*;
//! ```

// - internal
pub use crate::{
    constants::*,
    CompressionAlgorithm,
    EncryptionAlgorithm,
    footer::*,
    header::*,
    Hash,
    HashType,
    KDFScheme,
    PlatformString,
    PBEScheme,
    Result,
    traits::*,
    VirtualFileFooterMetadata,
    ZffError, ZffErrorKind,
};

pub(crate) use crate::{
    chunk::ChunkContent,
};