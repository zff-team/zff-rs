// - modules
mod error;
mod header;
mod constants;
mod traits;
mod compression;
mod encryption;
mod file_extension;

// - re-exports
pub use error::*;
pub use header::*;
pub use constants::*;
pub use traits::*;
pub use compression::*;
pub use encryption::*;
pub use file_extension::*;

// - types
pub type Result<T> = std::result::Result<T, ZffError>;