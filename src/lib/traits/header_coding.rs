//! Module for header encoding and decoding functionality.
//!
//! This module provides the [`HeaderCoding`] trait which defines the interface for
//! encoding and decoding header structures to and from byte streams.

// - STD
use std::any::type_name;
use std::borrow::Borrow;
use std::io::Read;

// - internal
use crate::{helper::decode_header_content_len, prelude::*};

// - external
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
#[cfg(feature = "log")]
use log::trace;

/// The `HeaderCoding` trait specifies an interface for the common header methods and the encoding and decoding methods.
pub trait HeaderCoding {
    /// the return value for decode_content(), decode_directly(), decode_for_key();
    type Item;

    /// returns the identifier (=Magic bytes) of the header.
    fn identifier() -> u32;

    /// encodes the (potentially encryptable) content of the struct.
    fn encode_content(&self) -> Vec<u8>;

    /// encodes the (non-encryptable) content of the struct.
    fn encode_fixed_fields(&self) -> Vec<u8> {
        Vec::new()
    }

    /// encodes the header.
    fn encode_header(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&Self::version().encode_directly());
        vec.extend_from_slice(&self.encode_fixed_fields());
        vec.extend_from_slice(&self.encode_content());
        vec
    }

    /// returns the size of the encoded header (in bytes)
    fn header_size(&self) -> usize {
        DEFAULT_LENGTH_HEADER_IDENTIFIER // Self::identifier() -> u32 -> 4 bytes
		+ DEFAULT_LENGTH_VALUE_HEADER_LENGTH // header size value itself -> u64 -> 8 bytes
		+ self.encode_header().len()
    }

    /// returns the version of the header.
    /// This reflects the default version of the appropriate header used in zff v3.
    fn version() -> u8;

    /// encodes a given key.
    fn encode_key<K: Into<String>>(key: K) -> Vec<u8> {
        let mut vec = Vec::new();
        let key = key.into();
        let key_length = key.len() as u8;
        vec.push(key_length);
        vec.append(&mut key.into_bytes());
        vec
    }
    /// encodes the (header) value/object directly (= without key).
    fn encode_directly(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&Self::identifier().to_be_bytes());
        vec.extend_from_slice(&self.header_size().to_le_bytes());
        vec.extend_from_slice(&self.encode_header());

        vec
    }

    /// decodes the length of the header.
    fn decode_header_length<R: Read>(data: &mut R) -> Result<u64> {
        match data.read_u64::<LittleEndian>() {
            Ok(value) => Ok(value),
            Err(_) => Err(ZffError::new(
                ZffErrorKind::EncodingError,
                ERROR_HEADER_DECODER_HEADER_LENGTH,
            )),
        }
    }

    /// checks if the read identifier is valid for this header.
    fn check_identifier<R: Read>(data: &mut R) -> bool {
        let identifier = match data.read_u32::<BigEndian>() {
            Ok(val) => val,
            Err(_) => return false,
        };
        #[cfg(feature = "log")]
        log::trace!("Read identifier: {:x}", identifier);
        identifier == Self::identifier()
    }

    /// checks if the read header / footer version is supported by this crate (only zff v3 headers / footers are supported).
    fn check_version<R: Read>(data: &mut R) -> Result<()> {
        let version = match data.read_u8() {
            Ok(val) => val,
            Err(_) => {
                return Err(ZffError::new(
                    ZffErrorKind::EncodingError,
                    ERROR_HEADER_DECODER_HEADER_LENGTH,
                ));
            }
        };
        if version != Self::version() {
            return Err(ZffError::new(
                ZffErrorKind::Unsupported,
                format!("{ERROR_UNSUPPORTED_VERSION}{version}"),
            ));
        }
        Ok(())
    }

    /// decodes the content of the header.
    fn decode_content(data: &[u8]) -> Result<Self::Item>;

    /// decodes the header directly.
    fn decode_directly<R: Read>(data: &mut R) -> Result<Self::Item> {
        #[cfg(feature = "log")]
        trace!("Trying to decode a {}", Self::struct_name());
        if !Self::check_identifier(data) {
            return Err(ZffError::new(
                ZffErrorKind::Invalid,
                ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER,
            ));
        }
        let header_content_length =
            decode_header_content_len(Self::decode_header_length(data)?, 0)?;
        let mut header_content = Vec::new();
        header_content.try_reserve_exact(header_content_length)?;
        header_content.resize(header_content_length, 0);
        data.read_exact(&mut header_content)?;
        Self::decode_content(&header_content)
    }

    /// decodes the header at given offset.
    fn decode_at<R: ReadAt + ?Sized>(data: &R, offset: u64) -> Result<Self::Item> {
        let mut cursor = ReadAtCursor::new(data, offset);
        Self::decode_directly(&mut cursor)
    }

    /// Method to show the "name" of the appropriate struct (e.g. to use this with fmt::Display).
    /// This method is a helper method for fmt::Display and serde::ser::SerializeStruct (and for some debugging purposes).
    fn struct_name() -> &'static str {
        let full_name = type_name::<Self>();
        // Split by "::" and take the last part
        full_name.split("::").last().unwrap_or(full_name)
    }
}

/// Trait which provides methods to encrypt a header.
pub trait HeaderEncryption: HeaderCoding + Encryption {
    /// Optional precondition to check if encryption is possible.
    /// true if encryption is possible, false if precondition fails.
    fn encryption_precondition(&self) -> bool {
        true
    }

    /// encodes the header to a ```Vec<u8>```.
    /// # Error
    /// The method returns an error, if the encryption header is missing (=None).
    /// The method returns an error, if the encryption fails.
    fn encrypt_directly<E: Borrow<EncryptionInformation>>(
        &self,
        encryption_information: E,
    ) -> Result<Vec<u8>> {
        let mut vec = Vec::new();

        let encoded_header = self.encode_encrypted_header(encryption_information)?;
        let identifier = Self::identifier();
        let length = 4 + 8 + (encoded_header.len() as u64);

        vec.extend_from_slice(&identifier.to_be_bytes());
        vec.extend_from_slice(&length.to_le_bytes());
        vec.extend_from_slice(&encoded_header);
        Ok(vec)
    }

    /// encrypts and encodes the header.
    fn encode_encrypted_header<E: Borrow<EncryptionInformation>>(
        &self,
        encryption_information: E,
    ) -> Result<Vec<u8>> {
        if !self.encryption_precondition() {
            return Err(ZffError::new(
                ZffErrorKind::EncryptionError,
                ERROR_ENCRYPTION_PRECONDITION_FAILED,
            ));
        };
        let mut vec = Vec::new();
        vec.extend_from_slice(&Self::version().encode_directly());
        vec.extend_from_slice(&self.encoded_fixed_fields_for_encryption());
        let mut data_to_encrypt = Vec::new();
        data_to_encrypt.extend_from_slice(&self.encode_content());

        let encrypted_data = Self::encrypt(
            &encryption_information.borrow().encryption_key,
            data_to_encrypt,
            self.nonce_value(),
            &encryption_information.borrow().algorithm,
        )?;
        vec.extend_from_slice(&encrypted_data.encode_directly());
        Ok(vec)
    }

    /// Sometimes, we have to set flag values...than, we have to modify the fixed fields.
    fn encoded_fixed_fields_for_encryption(&self) -> Vec<u8> {
        self.encode_fixed_fields()
    }

    /// The value which should be used to calculate the nonce (e.g. the filenumber for a FileHeader).
    fn nonce_value(&self) -> u64;
}
