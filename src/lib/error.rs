// - STD
use std::fmt;
use std::string::FromUtf8Error;
use std::io;

// - internal

// - external
use pkcs5::CryptoError as PKCS5CryptoError;
use aes_gcm_siv::aead::Error as EncryptionError;
use ed25519_dalek::ed25519::Error as Ed25519Error;
use base64::DecodeError as Base64DecodingError;
use lz4_flex::frame::Error as Lz4Error;

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
	/// Error will be returned, if no object type exists for the given value
	UnknownObjectTypeValue,
	/// Error will be returned, if you try to call a method, which is not available for this [FileType].
	NotAvailableForFileType,
	/// Error will be returned, if the underlying file type is not a File, a Directory or a Symlink.
	UnimplementedFileType,
	/// Error will be returned, if no files left in vector.
	NoFilesLeft,
}

impl fmt::Display for ZffErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let err_msg = match self {
			ZffErrorKind::IoError(_) => "IoError",
			ZffErrorKind::PKCS5CryptoError => "PKCS5CryptoError",
			ZffErrorKind::Custom => "Custom",
			ZffErrorKind::FileExtensionParserError => "FileExtensionParserError",
			ZffErrorKind::EncryptionError => "EncryptionError",
			ZffErrorKind::Ed25519Error => "Ed25519Error",
			ZffErrorKind::Base64DecodingError => "Base64DecodingError",
			ZffErrorKind::Lz4Error => "Lz4Error",
			ZffErrorKind::FromUtf8Error => "FromUtf8Error",
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
			ZffErrorKind::MainHeaderEncryptionError => "MainHeaderEncryptionError",
			ZffErrorKind::InvalidChunkNumber => "InvalidChunkNumber",
			ZffErrorKind::NoSignatureFoundAtChunk => "NoSignatureFoundAtChunk",
			ZffErrorKind::InvalidFlagValue => "InvalidFlagValue",
			ZffErrorKind::MissingSegment => "MissingSegment",
			ZffErrorKind::UnknownObjectTypeValue => "UnknownObjectTypeValue",
			ZffErrorKind::NotAvailableForFileType => "NotAvailableForFileType",
			ZffErrorKind::UnimplementedFileType => "UnimplementedFileType",
			ZffErrorKind::NoFilesLeft => "NoFilesLeft",

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
	/// use zff::{ZffError, Result};
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

	/// Creates a new crate-related header decode error.
	/// # Example
	/// ```
	/// use zff::{ZffError, Result};
	/// fn my_func() -> Result<()> {
	/// 	let decode_error = ZffError::new_header_decode_error("error while trying to decode CompressionHeader from given data");
	///		Err(decode_error)
	/// }
	/// fn main() {
	///		match my_func() {
	///			Err(x) => println!("It work's! Your custom error message is: {}", x),
	///			_ => ()
	///		}
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
	/// 	let custom_error = ZffError::new_custom("My detailed custom error message");
	///		Err(custom_error)
	/// }
	/// fn main() {
	/// 	match my_func() {
	/// 		Err(x) => {
	/// 			assert!(matches!(x.get_kind(), &ZffErrorKind::Custom));
	/// 		},
	/// 		_ => ()
	/// 	}
	/// }
	pub fn get_kind(&self) -> &ZffErrorKind {
		return &self.kind
	}

	/// returns the error kind and consumes self.
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
	/// 			assert!(matches!(x.unwrap_kind(), ZffErrorKind::Custom));
	/// 		},
	/// 		_ => ()
	/// 	}
	/// }
	pub fn unwrap_kind(self) -> ZffErrorKind {
		return self.kind
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

impl From<FromUtf8Error> for ZffError {
	fn from(e: FromUtf8Error) -> ZffError {
		ZffError::new(ZffErrorKind::FromUtf8Error, e.to_string())
	}
}

impl fmt::Display for ZffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let err_msg = format!("{}: {}", self.kind.to_string(), self.details);
		write!(f, "{}", err_msg)
	}
}