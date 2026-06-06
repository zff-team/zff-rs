//! Module for logical object source implementations.
//!
//! Logical object sources provide data for logical acquisitions (file system acquisitions).
//! This module contains implementations for different types of logical sources.
//!
//! # Modules
//!
//! - [`filesystem`]: Filesystem-based logical object source
//! - `los_tar`: TAR archive-based logical object source (available with `los_tar` feature)
//!
//! # Re-exports
//!
//! All logical object source types are re-exported here for convenient access.

// - modules
mod filesystem;
#[cfg(feature = "los_tar")]
mod los_tar;
// - re-exports
pub use filesystem::*;
#[cfg(feature = "los_tar")]
pub use los_tar::*;