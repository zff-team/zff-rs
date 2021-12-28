// - modules
pub mod version1;
pub mod version2;
pub mod constants;
mod hashing;
mod compression;
mod encryption;
mod traits;
mod error;
mod signatures;
mod file_extension;
mod io;

// - re-exports
pub use hashing::*;
pub use compression::*;
pub use encryption::*;
pub use error::*;
pub use signatures::*;
pub use traits::*;
pub use file_extension::*;
use io::*;
use constants::*;

// - types
/// Result for std::result::Result<T, ZffError>.
pub type Result<T> = std::result::Result<T, ZffError>;