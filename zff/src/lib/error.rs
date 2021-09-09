// - STD
use std::fmt;
use std::io;

// - internal

// - external
use pkcs5::CryptoError as PKCS5CryptoError;
use aes_gcm_siv::aead::Error as EncryptionError;
use ed25519_dalek::ed25519::Error as Ed25519Error;
use base64::DecodeError as Base64DecodingError;

/// The main error-type of this crate.
#[derive(Debug, Clone)]
pub struct ZffError {
	details: String,
	kind: ZffErrorKind,
}

/// Contains the variants/kinds of errors, which could be find in this crate.
#[derive(Debug, Clone)]
pub enum ZffErrorKind {
	/// contains a std::io::Error.
	IoError,
	/// contains a pkcs5::CryptoError.
	PKCS5CryptoError,
	/// Error which occurs when parsing the file extension.
	FileExtensionParserError,
	/// contains a aes_gcm_siv::aead::Error.
	EncryptionError,
	/// contains a ed25519_dalek::ed25519::Error.
	Ed25519Error,
	/// contains a base64::DecodeError.
	Base64DecodingError,
	/// If the signature key length is != 64.
	WrongSignatureKeyLength,
	/// If the encryption header is missing, but you call a method to encrypt the header or data.
	MissingEncryptionHeader,
	/// This is not an error in the strict sense. If you read a source file and reach the EOF,
	/// you will get this error kind to handle your next steps.
	ReadEOF,
	/// Custom errors.
	Custom,
}

impl fmt::Display for ZffErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let err_msg = match self {
			ZffErrorKind::IoError => "IoError",
			ZffErrorKind::PKCS5CryptoError => "PKCS5CryptoError",
			ZffErrorKind::Custom => "Custom",
			ZffErrorKind::FileExtensionParserError => "FileExtensionParserError",
			ZffErrorKind::EncryptionError => "EncryptionError",
			ZffErrorKind::Ed25519Error => "Ed25519Error",
			ZffErrorKind::Base64DecodingError => "Base64DecodingError",
			ZffErrorKind::WrongSignatureKeyLength => "WrongSignatureKeyLength",
			ZffErrorKind::MissingEncryptionHeader => "MissingEncryptionHeader",
			ZffErrorKind::ReadEOF => "ReadEOF",
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

	/// Creates a new crate-related custom error.
	/// # Example
	/// ```
	/// use zff::{ZffError, ZffErrorKind, Result};
	/// fn my_func() -> Result<()> {
	/// 	let custom_error = ZffError::new_custom("My detailed custom error message");
	///		Err(custom_error)
	/// }
	/// fn main() {
	///		match my_func() {
	///			Err(x) => println!("It work's! Your custom error message is: {}", x),
	///			_ => ()
	///		}
	/// }
	pub fn new_custom<S: Into<String>>(details: S) -> ZffError {
		ZffError {
			kind: ZffErrorKind::Custom,
			details: details.into()
		}
	}

	/// Returns the error kind.
	/// # Example
	/// ```
	/// use zff::{ZffError, ZffErrorKind, Result};
	/// fn my_func() -> Result<()> {
	/// 	let custom_error = ZffError::new_custom("My detailed custom error message");
	///		Err(custom_error)
	/// }
	/// fn main() {
	/// 	match my_func() {
	/// 		Err(x) => {
	/// 			assert_eq!(x.get_kind(), ZffErrorKind::Custom)
	/// 		},
	/// 		_ => ()
	/// 	}
	/// }
	pub fn get_kind(&self) -> &ZffErrorKind {
		return &self.kind
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

impl From<EncryptionError> for ZffError {
	fn from(e: EncryptionError) -> ZffError {
		ZffError::new(ZffErrorKind::EncryptionError, e.to_string())
	}
}

impl From<Ed25519Error> for ZffError {
	fn from(e: Ed25519Error) -> ZffError {
		ZffError::new(ZffErrorKind::Ed25519Error, e.to_string())
	}
}

impl From<Base64DecodingError> for ZffError {
	fn from(e: Base64DecodingError) -> ZffError {
		ZffError::new(ZffErrorKind::Base64DecodingError, e.to_string())
	}
}


impl fmt::Display for ZffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let err_msg = format!("{}: {}", self.kind.to_string(), self.details);
		write!(f, "{}", err_msg)
	}
}