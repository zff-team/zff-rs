//! Module for virtual object source implementations.
//!
//! Virtual object sources provide data for virtual acquisitions (e.g., RAID reconstruction,
//! concatenated images). This module contains implementations for different types
//! of virtual sources.
//!
//! # Modules
//!
//! - `vos_tar`: TAR archive-based virtual object source (available with `vos_tar` feature)
//!
//! # Re-exports
//!
//! All virtual object source types are re-exported here for convenient access.

// - modules
#[cfg(feature = "vos_tar")]
mod vos_tar;

// - re-exports
#[cfg(feature = "vos_tar")]
pub use vos_tar::*;