// - modules
pub mod version1;
pub mod version2;
mod error;

// - internal
pub use error::*;

// - types
/// Result for std::result::Result<T, ZffError>.
pub type Result<T> = std::result::Result<T, ZffError>;