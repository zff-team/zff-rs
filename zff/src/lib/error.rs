// - STD
use std::fmt;
use std::io;

// - internal

// - external
use pkcs5::CryptoError as PKCS5CryptoError;

/// The main error-type of this crate.
#[derive(Debug, Clone)]
pub struct ZffError {
	details: String,
	kind: ZffErrorKind,
}

/// Contains the variants/kinds of errors, which could be find in this crate.
#[derive(Debug, Clone)]
pub enum ZffErrorKind {
	IoError,
	PKCS5CryptoError,
	Custom,
}

impl fmt::Display for ZffErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let err_msg = match self {
			ZffErrorKind::IoError => "IoError",
			ZffErrorKind::PKCS5CryptoError => "PKCS5CryptoError",
			ZffErrorKind::Custom => "Custom",
		};
	write!(f, "{}", err_msg)
	}
}

impl ZffError {
	/// Creates a new crate-related error.
	/// # Example
	/// ```
	/// use zff::{ZffError, ZffErrorKind, Result};
	/// fn my_func() -> Result<()> {
	/// 	let custom_error = ZffError::new(
	///								ZffErrorKind::Custom, "My detailed custom error message");
	///		Err(custom_error)
	/// }
	/// fn main() {
	///		match my_func() {
	///			Err(x) => println!("It work's! Your custom error message is: {}", x),
	///			_ => ()
	///		}
	/// }
	pub fn new<S: Into<String>>(kind: ZffErrorKind, details: S) -> ZffError {
		ZffError {
			kind: kind,
			details: details.into()
		}
	}

	pub fn new_custom<S: Into<String>>(details: S) -> ZffError {
		ZffError {
			kind: ZffErrorKind::Custom,
			details: details.into()
		}
	}
}

impl From<io::Error> for ZffError {
	fn from(e: io::Error) -> ZffError {
		ZffError::new(ZffErrorKind::IoError, e.to_string())
	}
}

impl From<PKCS5CryptoError> for ZffError {
	fn from(e: PKCS5CryptoError) -> ZffError {
		ZffError::new(ZffErrorKind::PKCS5CryptoError, e.to_string())
	}
}

impl fmt::Display for ZffError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let err_msg = format!("{}: {}", self.kind.to_string(), self.details);
		write!(f, "{}", err_msg)
	}
}