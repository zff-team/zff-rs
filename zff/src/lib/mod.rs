// - modules
mod error;
mod header;
mod constants;
mod traits;
mod compression;
mod encryption;
mod file_extension;
mod io;
mod hashing;

// - re-exports
pub use error::*;
pub use header::*;
pub use constants::*;
pub use traits::*;
pub use compression::*;
pub use encryption::*;
pub use file_extension::*;
pub use io::*;
pub use hashing::*;

// - types
pub type Result<T> = std::result::Result<T, ZffError>;