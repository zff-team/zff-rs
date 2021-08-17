// - modules
mod error;
mod header;
mod constants;
mod traits;
mod compression;

// - re-exports
pub use error::*;
pub use header::*;
pub use constants::*;
pub use traits::*;
pub use compression::*;

// - types
pub type Result<T> = std::result::Result<T, ZffError>;