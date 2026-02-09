// - Parent
use super::*;

/// The main error-type of this crate.
#[derive(Debug)]
pub struct ZffError {
	/// A detailed error message.
	details: String,
	/// The source (if available)
	source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
	/// The appropriate [ZffErrorKind].
	kind: ZffErrorKind,
}

impl ZffError {
	/// Creates a new crate-related error.
	/// # Example
	/// ```
	/// use zff::{ZffError, ZffErrorKind, Result};
	/// fn my_func() -> Result<()> {
	/// 	let io_error = std::io::Error::new(std::io::ErrorKind::Other, "oh no!");
	///     let custom_error = ZffError::new_with_source(
	///                                ZffErrorKind::Custom,
	/// 							   Some(Box::new(io_error)),
	/// 							   "My detailed custom error message");
	///        Err(custom_error)
	/// }
	/// fn main() {
	///        match my_func() {
	///            Err(x) => println!("It work's! Your custom error message is: {}", x),
	///            _ => ()
	///        }
	/// }
	pub fn new_with_source<S: Into<String>>(
		kind: ZffErrorKind,
		source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
		details: S) -> Self {
			Self {
			kind,
			source,
			details: details.into(),
		}
	}

	/// Creates a new crate-related error.
	/// # Example
	/// ```
	/// use zff::{ZffError, ZffErrorKind, Result};
	/// fn my_func() -> Result<()> {
	///     let custom_error = ZffError::new(
	///                                ZffErrorKind::Custom, "My detailed custom error message");
	///        Err(custom_error)
	/// }
	/// fn main() {
	///        match my_func() {
	///            Err(x) => println!("It work's! Your custom error message is: {}", x),
	///            _ => ()
	///        }
	/// }
	pub fn new<S: Into<String>>(
		kind: ZffErrorKind,
		details: S) -> Self {
			Self {
			kind,
			source: None,
			details: details.into(),
		}
	}

	/// Creates a new crate-related custom error.
	/// # Example
	/// ```
	/// use zff::{ZffError, Result};
	/// fn my_func() -> Result<()> {
	///     let custom_error = ZffError::new_custom("My detailed custom error message");
	///        Err(custom_error)
	/// }
	/// fn main() {
	///        match my_func() {
	///            Err(x) => println!("It work's! Your custom error message is: {}", x),
	///            _ => ()
	///        }
	/// }
	pub fn new_custom<S: Into<String>>(details: S) -> ZffError {
		Self {
			details: details.into(),
			source: None,
			kind: ZffErrorKind::Custom,
		}
	}

	/// Returns a reference to the kind.
	/// # Example
	/// ```
	/// use zff::{ZffError, ZffErrorKind, Result};
	/// fn my_func() -> Result<()> {
	///     let custom_error = ZffError::new_custom("My detailed custom error message");
	///        Err(custom_error)
	/// }
	/// fn main() {
	///     match my_func() {
	///         Err(x) => {
	///             assert!(matches!(x.kind(), ZffErrorKind::Custom));
	///         },
	///         _ => ()
	///     }
	/// }
	pub fn kind_ref(&self) -> &ZffErrorKind {
		&self.kind
	}

	/// Returns a clone of the appropriate kind.
	/// # Example
	/// ```
	/// use zff::{ZffError, ZffErrorKind, Result};
	/// fn my_func() -> Result<()> {
	///     let custom_error = ZffError::new_custom("My detailed custom error message");
	///        Err(custom_error)
	/// }
	/// fn main() {
	///     match my_func() {
	///         Err(x) => {
	///             assert!(matches!(x.kind(), ZffErrorKind::Custom));
	///         },
	///         _ => ()
	///     }
	/// }
	pub fn kind(&self) -> ZffErrorKind {
		self.kind.clone()
	}

	/// returns the error kind and consumes self.
	/// # Example
	/// ```
	/// use zff::{ZffError, ZffErrorKind, Result};
	/// fn my_func() -> Result<()> {
	///     let custom_error = ZffError::new_custom("My detailed custom error message");
	///        Err(custom_error)
	/// }
	/// fn main() {
	///     match my_func() {
	///         Err(x) => {
	///             assert!(matches!(x.into_inner_kind(), ZffErrorKind::Custom));
	///         },
	///         _ => ()
	///     }
	/// }
	pub fn into_inner_kind(self) -> ZffErrorKind {
		self.kind
	}
}

impl std::error::Error for ZffError {
	/// Returns the source of this error, if any.
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		self.source.as_deref().map(|e| e as &(dyn std::error::Error + 'static))
	}
}

impl fmt::Display for ZffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let err_msg = format!("{}: {}", self.kind, self.details);
		write!(f, "{}", err_msg)
	}
}

impl From<ZffError> for std::io::Error {
	fn from(e: ZffError) -> std::io::Error {
		let err_msg = e.details;
		std::io::Error::new(std::io::ErrorKind::Other, err_msg)
	}
}

impl From<&ZffError> for ZffError {
	fn from(e: &ZffError) -> ZffError {
		e.into()
	}
}

impl From<ParseIntError> for ZffError {
	fn from(e: ParseIntError) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new_with_source(ZffErrorKind::ParsingError, Some(Box::new(e)), err_msg)
	}
}

impl From<AesCbcError> for ZffError {
	fn from(e: AesCbcError) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new_with_source(ZffErrorKind::EncryptionError, Some(Box::new(e)), err_msg)
	}
}

impl From<Argon2Error> for ZffError {
	fn from(e: Argon2Error) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new_with_source(ZffErrorKind::EncryptionError, Some(Box::new(e)), err_msg)
	}
}

impl From<RedbCommitError> for ZffError {
	fn from(e: RedbCommitError) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new_with_source(ZffErrorKind::DatabaseError, Some(Box::new(e)), err_msg)
	}
}

impl From<RedbStorageError> for ZffError {
	fn from(e: RedbStorageError) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new_with_source(ZffErrorKind::DatabaseError, Some(Box::new(e)), err_msg)
	}
}

impl From<RedbTableError> for ZffError {
	fn from(e: RedbTableError) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new_with_source(ZffErrorKind::DatabaseError, Some(Box::new(e)), err_msg)
	}
}

impl From<RedbTransactionError> for ZffError {
	fn from(e: RedbTransactionError) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new_with_source(ZffErrorKind::DatabaseError, Some(Box::new(e)), err_msg)
	}
}

impl From<RedbError> for ZffError {
	fn from(e: RedbError) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new_with_source(ZffErrorKind::DatabaseError, Some(Box::new(e)), err_msg)
	}
}

impl From<std::io::Error> for ZffError {
	fn from(e: std::io::Error) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new_with_source(ZffErrorKind::IO, Some(Box::new(e)), err_msg)
	}
}

impl From<PKCS5CryptoError> for ZffError {
	fn from(e: PKCS5CryptoError) -> ZffError {
		let err_msg = e.to_string();
		//TODO: time of writing, pkcs5 does not implement std::error::Error (stable is version 0.7.1, 0.8.0
		// is just a release canidate which implements std::error::Error using the feature-flag std).
		// As soon as version 0.8.0 is released, we can use the source of the error.
		ZffError::new_with_source(ZffErrorKind::EncryptionError, None, err_msg)
	}
}

impl From<ScryptErrorInvalidParams> for ZffError {
	fn from(e: ScryptErrorInvalidParams) -> ZffError {
		let err_msg = e.to_string();
		//TODO: time of writing, pkcs5 does not implement std::error::Error (stable is version 0.7.1, 0.8.0
		// is just a release canidate which implements std::error::Error using the feature-flag std).
		// As soon as version 0.8.0 is released, we can use the source of the error.
		ZffError::new_with_source(ZffErrorKind::Invalid, None, err_msg)
	}
}

impl From<AesError> for ZffError {
	fn from(e: AesError) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new_with_source(ZffErrorKind::EncryptionError, Some(Box::new(e)), err_msg)
	}
}

impl From<Lz4Error> for ZffError {
	fn from(e: Lz4Error) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new_with_source(ZffErrorKind::CompressionError, Some(Box::new(e)), err_msg)
	}
}

impl From<Ed25519Error> for ZffError {
	fn from(e: Ed25519Error) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new_with_source(ZffErrorKind::SigningError, Some(Box::new(e)), err_msg)
	}
}

impl From<Base64DecodingError> for ZffError {
	fn from(e: Base64DecodingError) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new_with_source(ZffErrorKind::EncodingError, Some(Box::new(e)), err_msg)
	}
}

impl From<ComponentRangeError> for ZffError {
	fn from(e: ComponentRangeError) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new_with_source(ZffErrorKind::Other, Some(Box::new(e)), err_msg)
	}
}

impl From<FromUtf8Error> for ZffError {
	fn from(e: FromUtf8Error) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new_with_source(ZffErrorKind::EncodingError, Some(Box::new(e)), err_msg)
	}
}

impl From<TryReserveError> for ZffError {
	fn from(e: TryReserveError) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new_with_source(ZffErrorKind::Other, Some(Box::new(e)), err_msg)
	}
}

impl From<InvalidLength> for ZffError {
	fn from(e: InvalidLength) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new_with_source(ZffErrorKind::Invalid, Some(Box::new(e)), err_msg)
	}
}

/// Contains the variants/kinds of errors, which could be find in this crate.
#[derive(Debug, Clone)]
pub enum ZffErrorKind {
	/// An IO Error.
	IO,
	/// Contains an error within an encryption or decryption process.
	EncryptionError,
	/// Contains an error within a signing or verification process.
	SigningError,
	/// Contains an error within an encoding or decoding process.
	EncodingError,
	/// If an encoding key is not on position.
	KeyNotOnPosition,
	/// Contains an error while parsing data.
	ParsingError,
	/// Contains an error while reading or writing to the database.
	DatabaseError,
	/// Contains an error which occurs while compressing or decompressing data.
	CompressionError,
	/// This error occurs, if the data that was looked for are not found
	/// (e.g. a file number is not found, a chunk header is not found, etc.).
	NotFound,
	/// This error occurs, if the selected option or the given data, or something else is invalid.
	Invalid,
	/// This error occurs, if some expected things are missing.
	Missing,
	/// This error occurs, if no data is left in a data structure, which was expected to contain data.
	NoDataLeft,
	/// The error occurs, if the selected option or given data is unsupported.
	Unsupported,
	/// This error handles all other errors.
	Other,
	/// Custom errors.
	Custom,
}

impl fmt::Display for ZffErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let err_msg = match self {
			ZffErrorKind::IO => "IO",
			ZffErrorKind::EncryptionError => "Encryption",
			ZffErrorKind::SigningError => "Signing",
			ZffErrorKind::EncodingError => "Encoding",
			ZffErrorKind::KeyNotOnPosition => "KeyNotOnPosition",
			ZffErrorKind::ParsingError => "Parsing",
			ZffErrorKind::DatabaseError => "Database",
			ZffErrorKind::CompressionError => "Compression",
			ZffErrorKind::NotFound => "NotFound",
			ZffErrorKind::Invalid => "Invalid",
			ZffErrorKind::Missing => "Missing",
			ZffErrorKind::NoDataLeft => "NoDataLeft",
			ZffErrorKind::Unsupported => "Unsupported",
			ZffErrorKind::Other => "Other",
			ZffErrorKind::Custom => "Custom",
		};
	write!(f, "{}", err_msg)
	}
}