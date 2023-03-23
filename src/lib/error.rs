// - STD
use std::fmt;
use std::string::FromUtf8Error;
use std::io;
use std::collections::TryReserveError;

// - internal

// - external
use pkcs5::Error as PKCS5CryptoError;
use scrypt::errors::InvalidParams as ScryptErrorInvalidParams;
use aes_gcm_siv::aead::Error as EncryptionError;
use ed25519_dalek::ed25519::Error as Ed25519Error;
use base64::DecodeError as Base64DecodingError;
use lz4_flex::frame::Error as Lz4Error;
use time::error::ComponentRange as ComponentRangeError;

/// The main error-type of this crate.
#[derive(Debug)]
pub struct ZffError {
	details: String,
	kind: ZffErrorKind,
}

/// Contains the variants/kinds of errors, which could be find in this crate.
#[derive(Debug)]
pub enum ZffErrorKind {
	/// contains a std::io::Error.
	IoError(io::Error),
	/// contains a pkcs5::CryptoError.
	PKCS5CryptoError,
	/// contains a scrypt::errors::InvalidParams.
	ScryptErrorInvalidParams,
	/// contains a STD FromUtf8Error.
	FromUtf8Error,
	/// Error which occurs when parsing the file extension.
	FileExtensionParserError,
	/// contains a aes_gcm_siv::aead::Error.
	EncryptionError,
	/// contains a ed25519_dalek::ed25519::Error.
	Ed25519Error,
	/// contains a base64::DecodeError.
	Base64DecodingError,
	/// contains a time::error::ComponentRange.
	ComponentRangeError,
	/// If the signature key length is != 64.
	WrongSignatureKeyLength,
	/// If an error occures while compressing the input data with the lz4-algorithm.
	Lz4Error,
	/// If the encryption header is missing, but you call a method to encrypt the header or data.
	MissingEncryptionHeader,
	/// Error returns, if an encryption operation expect an encryption key but none is given.
	MissingEncryptionKey,
	/// Error will be returned, if the decryption of the inner encryption key fails.
	DecryptionOfEncryptionKey,
	/// This is not an error in the strict sense. If you read a source file and reach the EOF,
	/// you will get this error kind to handle your next steps.
	ReadEOF,
	/// This error will be returned, if the input stream was interrupted. Interrupted operations can typically be retried.
	InterruptedInputStream,
	/// This error will be returned, if the output stream was interrupted. Interrupted operations can typically be retried.
	InterruptedOutputStream,
	/// Custom errors.
	Custom,
	/// Error will be returned, if the given filetype is unknown.
	UnknownFileType,
	/// Error will be returned, if the file number for the hard link is missing
	MissingHardlinkFilenumber,
	/// Error will be returned, if the data could not be decoded to the given header.
	HeaderDecodeError,
	/// Error will be returned, if the read identifier mismatch with the header identifier.
	HeaderDecodeMismatchIdentifier,
	/// Error will be returned, if the given value key is not on position.
	HeaderDecoderKeyNotOnPosition,
	/// Error will be returned, if header is encrypted.
	HeaderDecodeEncryptedHeader,
	/// Error will be returned, if you try to get the data of a chunk number which not exists in this segment.
	DataDecodeChunkNumberNotInSegment,
	/// Error will be returned, if you try to create a segment with a segment number < 1;
	NullOrNegativeSegmentNumber,
	/// Error will be returned, if the segment size is too small.
	SegmentSizeToSmall,
	/// Error will be returned, if an object footer is present in segments, but no appropriate object header
	MissingObjectHeaderForPresentObjectFooter,
	/// Error will be returned, if the object number looked for does not exist.
	MissingObjectNumber,
	/// Error will be returned, if the file number looked for does not exist.
	MissingFileNumber,
	/// Error will be returned, if a needed password is not present.
	MissingPassword,
	/// Error will be returned, if the object number mismatches the given object type.
	MismatchObjectType,
	/// Error will be returned, if the main header could not be encrypted.
	MainHeaderEncryptionError,
	/// Error will be returned, if the chunk number is not present in zff image.
	InvalidChunkNumber,
	/// Error will be returned, if the selected chunk hasn't have an ed25519 signature.
	NoSignatureFoundAtChunk,
	/// Error will be returned, if there is an invalid flag value.
	InvalidFlagValue,
	/// Error will be returned, if the appropriate segment is missing in the zff image.
	MissingSegment,
	/// Error will be returned, if the appropriate segment is malformed (e.g. the object header is missing)
	MalformedSegment,
	/// Error will be returned, if the header is malformed.
	MalformedHeader,
	/// Error will be returned, if no object type exists for the given value
	UnknownObjectTypeValue,
	/// Error will be returned, if you try to call a method, which is not available for this [FileType].
	NotAvailableForFileType,
	/// Error will be returned, if the underlying file type is not a File, a Directory or a Symlink.
	UnimplementedFileType,
	/// Error will be returned, if no files left in vector.
	NoFilesLeft,
	/// Error will be returned, if no objects left in vector/map.
	NoObjectsLeft,
	/// Error will be returned, if no chunks left in vector/map.
	NoChunksLeft,
	/// Error for Seek.
	Seek,
	/// Error will be returned, if the operation is not possible because of missing memory capacity.
	OutOfMemory,
}

impl fmt::Display for ZffErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let err_msg = match self {
			ZffErrorKind::IoError(_) => "IoError",
			ZffErrorKind::PKCS5CryptoError => "PKCS5CryptoError",
			ZffErrorKind::ScryptErrorInvalidParams => "ScryptErrorInvalidParams",
			ZffErrorKind::Custom => "Custom",
			ZffErrorKind::MissingHardlinkFilenumber => "MissingHardlinkFilenumber",
			ZffErrorKind::FileExtensionParserError => "FileExtensionParserError",
			ZffErrorKind::EncryptionError => "EncryptionError",
			ZffErrorKind::Ed25519Error => "Ed25519Error",
			ZffErrorKind::Base64DecodingError => "Base64DecodingError",
			ZffErrorKind::ComponentRangeError => "ComponentRangeError",
			ZffErrorKind::Lz4Error => "Lz4Error",
			ZffErrorKind::FromUtf8Error => "FromUtf8Error",
			ZffErrorKind::UnknownFileType => "UnknownFileType",
			ZffErrorKind::WrongSignatureKeyLength => "WrongSignatureKeyLength",
			ZffErrorKind::MissingEncryptionHeader => "MissingEncryptionHeader",
			ZffErrorKind::MissingEncryptionKey => "MissingEncryptionKey",
			ZffErrorKind::DecryptionOfEncryptionKey => "DecryptionOfEncryptionKey",
			ZffErrorKind::ReadEOF => "ReadEOF",
			ZffErrorKind::InterruptedInputStream => "InterruptedInputStream",
			ZffErrorKind::InterruptedOutputStream => "InterruptedOutputStream",
			ZffErrorKind::HeaderDecodeError => "HeaderDecodeError",
			ZffErrorKind::HeaderDecodeMismatchIdentifier => "HeaderDecodeMismatchIdentifier",
			ZffErrorKind::HeaderDecoderKeyNotOnPosition => "HeaderDecoderKeyNotOnPosition",
			ZffErrorKind::HeaderDecodeEncryptedHeader => "HeaderDecodeEncryptedHeader",
			ZffErrorKind::DataDecodeChunkNumberNotInSegment => "DataDecodeChunkNumberNotInSegment",
			ZffErrorKind::NullOrNegativeSegmentNumber => "NullOrNegativeSegmentNumber",
			ZffErrorKind::SegmentSizeToSmall => "SegmentSizeToSmall",
			ZffErrorKind::MissingObjectHeaderForPresentObjectFooter => "MissingObjectHeaderForPresentObjectFooter",
			ZffErrorKind::MissingObjectNumber => "MissingObjectNumber",
			ZffErrorKind::MissingFileNumber => "MissingFileNumber",
			ZffErrorKind::MissingPassword => "MissingPassword",
			ZffErrorKind::MismatchObjectType => "MismatchObjectType",
			ZffErrorKind::MainHeaderEncryptionError => "MainHeaderEncryptionError",
			ZffErrorKind::InvalidChunkNumber => "InvalidChunkNumber",
			ZffErrorKind::NoSignatureFoundAtChunk => "NoSignatureFoundAtChunk",
			ZffErrorKind::InvalidFlagValue => "InvalidFlagValue",
			ZffErrorKind::MissingSegment => "MissingSegment",
			ZffErrorKind::MalformedSegment => "MalformedSegment",
			ZffErrorKind::MalformedHeader => "MalformedHeader",
			ZffErrorKind::UnknownObjectTypeValue => "UnknownObjectTypeValue",
			ZffErrorKind::NotAvailableForFileType => "NotAvailableForFileType",
			ZffErrorKind::UnimplementedFileType => "UnimplementedFileType",
			ZffErrorKind::NoFilesLeft => "NoFilesLeft",
			ZffErrorKind::NoObjectsLeft => "NoObjectsLeft",
			ZffErrorKind::NoChunksLeft => "NoChunksLeft",
			ZffErrorKind::Seek => "Seek",
			ZffErrorKind::OutOfMemory => "OutOfMemory",
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
	pub fn new<S: Into<String>>(kind: ZffErrorKind, details: S) -> ZffError {
		ZffError {
			kind,
			details: details.into()
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
		ZffError {
			kind: ZffErrorKind::Custom,
			details: details.into()
		}
	}

	/// Creates a new crate-related header decode error.
	/// # Example
	/// ```
	/// use zff::{ZffError, Result};
	/// fn my_func() -> Result<()> {
	///     let decode_error = ZffError::new_header_decode_error("error while trying to decode CompressionHeader from given data");
	///        Err(decode_error)
	/// }
	/// fn main() {
	///        match my_func() {
	///            Err(x) => println!("It work's! Your custom error message is: {}", x),
	///            _ => ()
	///        }
	/// }
	pub fn new_header_decode_error<S: Into<String>>(details: S) -> ZffError {
		ZffError {
			kind: ZffErrorKind::HeaderDecodeError,
			details: details.into(),
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
	///             assert!(matches!(x.get_kind(), &ZffErrorKind::Custom));
	///         },
	///         _ => ()
	///     }
	/// }
	pub fn get_kind(&self) -> &ZffErrorKind {
		&self.kind
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
	///             assert!(matches!(x.unwrap_kind(), ZffErrorKind::Custom));
	///         },
	///         _ => ()
	///     }
	/// }
	pub fn unwrap_kind(self) -> ZffErrorKind {
		self.kind
	}
}

impl From<io::Error> for ZffError {
	fn from(e: io::Error) -> ZffError {
		let err_msg = e.to_string();
		ZffError::new(ZffErrorKind::IoError(e), err_msg)
	}
}

impl From<PKCS5CryptoError> for ZffError {
	fn from(e: PKCS5CryptoError) -> ZffError {
		ZffError::new(ZffErrorKind::PKCS5CryptoError, e.to_string())
	}
}

impl From<ScryptErrorInvalidParams> for ZffError {
	fn from(e: ScryptErrorInvalidParams) -> ZffError {
		ZffError::new(ZffErrorKind::ScryptErrorInvalidParams, e.to_string())
	}
}

impl From<EncryptionError> for ZffError {
	fn from(e: EncryptionError) -> ZffError {
		ZffError::new(ZffErrorKind::EncryptionError, e.to_string())
	}
}

impl From<Lz4Error> for ZffError {
	fn from(e: Lz4Error) -> ZffError {
		ZffError::new(ZffErrorKind::Lz4Error, e.to_string())
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

impl From<ComponentRangeError> for ZffError {
	fn from(e: ComponentRangeError) -> ZffError {
		ZffError::new(ZffErrorKind::ComponentRangeError, e.to_string())
	}
}

impl From<FromUtf8Error> for ZffError {
	fn from(e: FromUtf8Error) -> ZffError {
		ZffError::new(ZffErrorKind::FromUtf8Error, e.to_string())
	}
}

impl From<TryReserveError> for ZffError {
	fn from(e: TryReserveError) -> ZffError {
		ZffError::new(ZffErrorKind::OutOfMemory, e.to_string())
	}
}

impl fmt::Display for ZffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let err_msg = format!("{}: {}", self.kind, self.details);
		write!(f, "{}", err_msg)
	}
}