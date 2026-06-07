// - STD
use std::borrow::Borrow;
use std::fmt;
use std::io::{Cursor, Read};

// - internal
use crate::prelude::*;

// - external
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// An [ObjectFooterPhysical] is written at the end of each physical object.
/// This footer contains various information about the acquisition process:
/// - the acquisition start time
/// - the acquisition start time
/// - the size of the (uncompressed and unencrypted) underlying data
/// - the first chunk number, which is used for this physical dump
/// - the total number of chunks, used for this physical dump
/// - a hash header with the appropriate hash values of the underlying physical dump
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ObjectFooterPhysical {
    /// The object number of the footer.
    pub object_number: u64,
    /// The acquisition start timestamp of the footer.
    pub acquisition_start: u64,
    /// The acquisition end timestamp of the footer.
    pub acquisition_end: u64,
    /// The original length of the data.
    pub length_of_data: u64,
    /// The first used chunk number in this object.
    pub first_chunk_number: u64,
    /// The total number of chunks used in this object.
    pub number_of_chunks: u64,
    /// The appropriate [crate::header::HashHeader].
    pub hash_header: HashHeader,
}

impl ObjectFooterPhysical {
    /// creates a new [ObjectFooterPhysical] with the given values.
    pub fn new(
        object_number: u64,
        acquisition_start: u64,
        acquisition_end: u64,
        length_of_data: u64,
        first_chunk_number: u64,
        number_of_chunks: u64,
        hash_header: HashHeader,
    ) -> ObjectFooterPhysical {
        Self {
            object_number,
            acquisition_start,
            acquisition_end,
            length_of_data,
            first_chunk_number,
            number_of_chunks,
            hash_header,
        }
    }

    pub(crate) fn decode_inner_content<R: Read>(
        data: &mut R,
    ) -> Result<(
        u64,        //acquisition_start
        u64,        //acquisition_end
        u64,        //length_of_data
        u64,        //first_chunk_number
        u64,        //number_of_chunks
        HashHeader, // hash_header
    )> {
        let acquisition_start = u64::decode_directly(data)?;
        let acquisition_end = u64::decode_directly(data)?;
        let length_of_data = u64::decode_directly(data)?;
        let first_chunk_number = u64::decode_directly(data)?;
        let number_of_chunks = u64::decode_directly(data)?;
        let hash_header = HashHeader::decode_directly(data)?;
        Ok((
            acquisition_start,
            acquisition_end,
            length_of_data,
            first_chunk_number,
            number_of_chunks,
            hash_header,
        ))
    }
}

// - implement fmt::Display
impl fmt::Display for ObjectFooterPhysical {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::struct_name())
    }
}

impl HeaderEncryption for ObjectFooterPhysical {
    fn nonce_value(&self) -> u64 {
        self.object_number
    }

    fn encoded_fixed_fields_for_encryption(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.object_number.encode_directly());
        vec.extend_from_slice(&true.encode_directly()); // encryption flag
        vec
    }
}

impl Encryption for ObjectFooterPhysical {
    fn crypto_nonce_padding() -> u8 {
        ObjectFooter::crypto_nonce_padding()
    }
}

impl HeaderCoding for ObjectFooterPhysical {
    type Item = Self;

    fn version() -> u8 {
        DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_PHYSICAL
    }
    fn identifier() -> u32 {
        FOOTER_IDENTIFIER_OBJECT_FOOTER_PHYSICAL
    }

    fn encode_content(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.acquisition_start.encode_directly());
        vec.extend_from_slice(&self.acquisition_end.encode_directly());
        vec.extend_from_slice(&self.length_of_data.encode_directly());
        vec.extend_from_slice(&self.first_chunk_number.encode_directly());
        vec.extend_from_slice(&self.number_of_chunks.encode_directly());
        vec.extend_from_slice(&self.hash_header.encode_directly());
        vec
    }

    fn encode_fixed_fields(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.object_number.encode_directly());
        vec.extend_from_slice(&false.encode_directly()); // encryption flag
        vec
    }

    fn decode_content(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        Self::check_version(&mut cursor)?;
        let object_number = u64::decode_directly(&mut cursor)?;
        let encryption_flag = bool::decode_directly(&mut cursor)?;
        if encryption_flag {
            return Err(ZffError::new(
                ZffErrorKind::Missing,
                ERROR_MISSING_ENCRYPTION_HEADER_KEY,
            ));
        }
        let (
            acquisition_start,
            acquisition_end,
            length_of_data,
            first_chunk_number,
            number_of_chunks,
            hash_header,
        ) = Self::decode_inner_content(&mut cursor)?;
        Ok(ObjectFooterPhysical::new(
            object_number,
            acquisition_start,
            acquisition_end,
            length_of_data,
            first_chunk_number,
            number_of_chunks,
            hash_header,
        ))
    }
}

/// Represents an encrypted object footer of a physical object.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct EncryptedObjectFooterPhysical {
    /// The appropriate object number.
    pub object_number: u64,
    /// The underlying data in encrypted form.
    pub encrypted_data: Vec<u8>,
}

impl EncryptedObjectFooterPhysical {
    /// Creates a new [EncryptedObjectFooterPhysical] by the given values.
    pub fn new(object_number: u64, encrypted_data: Vec<u8>) -> Self {
        Self {
            object_number,
            encrypted_data,
        }
    }

    /// Tries to decrypt the ObjectFooter. If an error occures, the EncryptedObjectFooterPhysical is still available.
    pub fn decrypt<A, K>(&self, key: K, algorithm: A) -> Result<ObjectFooterPhysical>
    where
        A: Borrow<EncryptionAlgorithm>,
        K: AsRef<[u8]>,
    {
        let content = ObjectFooter::decrypt(
            key,
            &self.encrypted_data,
            self.object_number,
            algorithm.borrow(),
        )?;
        let mut cursor = Cursor::new(content);
        let (
            acquisition_start,
            acquisition_end,
            length_of_data,
            first_chunk_number,
            number_of_chunks,
            hash_header,
        ) = ObjectFooterPhysical::decode_inner_content(&mut cursor)?;
        Ok(ObjectFooterPhysical::new(
            self.object_number,
            acquisition_start,
            acquisition_end,
            length_of_data,
            first_chunk_number,
            number_of_chunks,
            hash_header,
        ))
    }

    /// Tries to decrypt the ObjectFooter. Consumes the EncryptedObjectFooterPhysical, regardless of whether an error occurs or not.
    pub fn decrypt_and_consume<A, K>(self, key: K, algorithm: A) -> Result<ObjectFooterPhysical>
    where
        A: Borrow<EncryptionAlgorithm>,
        K: AsRef<[u8]>,
    {
        self.decrypt(key, algorithm)
    }
}

// - implement fmt::Display
impl fmt::Display for EncryptedObjectFooterPhysical {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::struct_name())
    }
}

impl HeaderCoding for EncryptedObjectFooterPhysical {
    type Item = Self;

    fn version() -> u8 {
        DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_PHYSICAL
    }
    fn identifier() -> u32 {
        FOOTER_IDENTIFIER_OBJECT_FOOTER_PHYSICAL
    }
    fn encode_content(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.object_number.encode_directly());
        vec.extend_from_slice(&true.encode_directly()); // encryption flag
        vec.extend_from_slice(&self.encrypted_data.encode_directly());
        vec
    }
    fn decode_content(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        Self::check_version(&mut cursor)?;
        let object_number = u64::decode_directly(&mut cursor)?;
        let encryption_flag = bool::decode_directly(&mut cursor)?;
        if !encryption_flag {
            return Err(ZffError::new(
                ZffErrorKind::EncryptionError,
                ERROR_DECODE_UNENCRYPTED_OBJECT_WITH_DECRYPTION_FN,
            ));
        }
        let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
        Ok(Self::new(object_number, encrypted_data))
    }
}
