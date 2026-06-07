// - STD
use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt;
use std::io::{Cursor, Read};

// - internal
use crate::prelude::*;

// - external
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// An [ObjectFooterLogical] is written at the end of each logical object container.
/// This footer contains various information about the acquisition process:
/// - the acquisition start time
/// - the acquisition start time
/// - a [Vec] of the filenumbers of the appropriate files in the root directory
/// - a [HashMap] in which segment numbers the corresponding file headers can be found.
/// - a [HashMap] in which offsets of the corresponding file headers can be found.
/// - a [HashMap] in which segment numbers the corresponding file footers can be found.
/// - a [HashMap] in which offsets the corresponding file footers can be found.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ObjectFooterLogical {
    /// The object number of the footer.
    pub object_number: u64,
    /// The acquisition start timestamp of the footer.
    pub acquisition_start: u64,
    /// The acquisition end timestamp of the footer.
    pub acquisition_end: u64,
    /// The filenumbers which are children of the root directory.
    pub root_dir_filenumbers: Vec<u64>,
    /// the segment number where the appropriate file header can be found.
    pub file_header_segment_numbers: HashMap<u64, u64>,
    /// the offset where the appropriate file header can be found.
    pub file_header_offsets: HashMap<u64, u64>,
    /// the segment number where the appropriate file footer can be found.
    pub file_footer_segment_numbers: HashMap<u64, u64>,
    /// the offset where the appropriate file footer can be found.
    pub file_footer_offsets: HashMap<u64, u64>,
}

impl ObjectFooterLogical {
    /// creates a new empty [ObjectFooterLogical]
    pub fn new_empty(object_number: u64) -> ObjectFooterLogical {
        Self {
            object_number,
            acquisition_start: 0,
            acquisition_end: 0,
            root_dir_filenumbers: Vec::new(),
            file_header_segment_numbers: HashMap::new(),
            file_header_offsets: HashMap::new(),
            file_footer_segment_numbers: HashMap::new(),
            file_footer_offsets: HashMap::new(),
        }
    }

    /// creates a new [ObjectFooterLogical] with the given values.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        object_number: u64,
        acquisition_start: u64,
        acquisition_end: u64,
        root_dir_filenumbers: Vec<u64>,
        file_header_segment_numbers: HashMap<u64, u64>,
        file_header_offsets: HashMap<u64, u64>,
        file_footer_segment_numbers: HashMap<u64, u64>,
        file_footer_offsets: HashMap<u64, u64>,
    ) -> ObjectFooterLogical {
        Self {
            object_number,
            acquisition_start,
            acquisition_end,
            root_dir_filenumbers,
            file_header_segment_numbers,
            file_header_offsets,
            file_footer_segment_numbers,
            file_footer_offsets,
        }
    }

    /// Replaces the underlying [Vec] with the given one.
    pub fn replace_root_dir_filenumbers(&mut self, filenumbers: &[u64]) {
        self.root_dir_filenumbers.clear();
        self.root_dir_filenumbers.extend_from_slice(filenumbers);
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn decode_inner_content<R: Read>(
        data: &mut R,
    ) -> Result<(
        u64,               //acquisition_start
        u64,               //acquisition_end
        Vec<u64>,          //root_dir_filenumbers
        HashMap<u64, u64>, //file_header_segment_numbers
        HashMap<u64, u64>, //file_header_offsets
        HashMap<u64, u64>, //file_footer_segment_numbers
        HashMap<u64, u64>, //file_footer_offsets
    )> {
        let acquisition_start = u64::decode_directly(data)?;
        let acquisition_end = u64::decode_directly(data)?;
        let root_dir_filenumbers = Vec::<u64>::decode_directly(data)?;
        let file_header_segment_numbers = HashMap::<u64, u64>::decode_directly(data)?;
        let file_header_offsets = HashMap::<u64, u64>::decode_directly(data)?;
        let file_footer_segment_numbers = HashMap::<u64, u64>::decode_directly(data)?;
        let file_footer_offsets = HashMap::<u64, u64>::decode_directly(data)?;
        Ok((
            acquisition_start,
            acquisition_end,
            root_dir_filenumbers,
            file_header_segment_numbers,
            file_header_offsets,
            file_footer_segment_numbers,
            file_footer_offsets,
        ))
    }
}

// - implement fmt::Display
impl fmt::Display for ObjectFooterLogical {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::struct_name())
    }
}

impl HeaderEncryption for ObjectFooterLogical {
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

impl Encryption for ObjectFooterLogical {
    fn crypto_nonce_padding() -> u8 {
        ObjectFooter::crypto_nonce_padding()
    }
}

impl HeaderCoding for ObjectFooterLogical {
    type Item = ObjectFooterLogical;

    fn version() -> u8 {
        DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_LOGICAL
    }
    fn identifier() -> u32 {
        FOOTER_IDENTIFIER_OBJECT_FOOTER_LOGICAL
    }

    fn encode_content(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.acquisition_start.encode_directly());
        vec.extend_from_slice(&self.acquisition_end.encode_directly());
        vec.extend_from_slice(&self.root_dir_filenumbers.encode_directly());
        vec.extend_from_slice(&self.file_header_segment_numbers.encode_directly());
        vec.extend_from_slice(&self.file_header_offsets.encode_directly());
        vec.extend_from_slice(&self.file_footer_segment_numbers.encode_directly());
        vec.extend_from_slice(&self.file_footer_offsets.encode_directly());
        vec
    }

    fn encode_fixed_fields(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.object_number.encode_directly());
        vec.extend_from_slice(&false.encode_directly()); // encryption flag
        vec
    }

    fn decode_content(data: &[u8]) -> Result<ObjectFooterLogical> {
        let mut cursor = Cursor::new(data);
        Self::check_version(&mut cursor)?; // check version (and skip it)
        let object_number = u64::decode_directly(&mut cursor)?;
        let encryption_flag = bool::decode_directly(&mut cursor)?;
        if encryption_flag {
            return Err(ZffError::new(
                ZffErrorKind::EncodingError,
                ERROR_MISSING_ENCRYPTION_HEADER_KEY,
            ));
        }
        let (
            acquisition_start,
            acquisition_end,
            root_dir_filenumbers,
            file_header_segment_numbers,
            file_header_offsets,
            file_footer_segment_numbers,
            file_footer_offsets,
        ) = Self::decode_inner_content(&mut cursor)?;
        Ok(ObjectFooterLogical::new(
            object_number,
            acquisition_start,
            acquisition_end,
            root_dir_filenumbers,
            file_header_segment_numbers,
            file_header_offsets,
            file_footer_segment_numbers,
            file_footer_offsets,
        ))
    }
}

/// An object footer for a logical object in encrypted form.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct EncryptedObjectFooterLogical {
    /// The appropriate object number.
    pub object_number: u64,
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::helper::buffer_to_hex",
            deserialize_with = "crate::helper::hex_to_buffer"
        )
    )]
    /// the encrypted data of this footer
    pub encrypted_data: Vec<u8>,
}

impl EncryptedObjectFooterLogical {
    /// Creates a new [EncryptedObjectFooterLogical] by the given values.
    pub fn new(object_number: u64, encrypted_data: Vec<u8>) -> Self {
        Self {
            object_number,
            encrypted_data,
        }
    }

    /// Tries to decrypt the ObjectFooter. If an error occures, the EncryptedObjectFooterPhysical is still available.
    pub fn decrypt<A, K>(&self, key: K, algorithm: A) -> Result<ObjectFooterLogical>
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
            root_dir_filenumbers,
            file_header_segment_numbers,
            file_header_offsets,
            file_footer_segment_numbers,
            file_footer_offsets,
        ) = ObjectFooterLogical::decode_inner_content(&mut cursor)?;
        Ok(ObjectFooterLogical::new(
            self.object_number,
            acquisition_start,
            acquisition_end,
            root_dir_filenumbers,
            file_header_segment_numbers,
            file_header_offsets,
            file_footer_segment_numbers,
            file_footer_offsets,
        ))
    }

    /// Tries to decrypt the ObjectFooter. Consumes the EncryptedObjectFooterPhysical, regardless of whether an error occurs or not.
    pub fn decrypt_and_consume<A, K>(self, key: K, algorithm: A) -> Result<ObjectFooterLogical>
    where
        A: Borrow<EncryptionAlgorithm>,
        K: AsRef<[u8]>,
    {
        self.decrypt(key, algorithm)
    }
}

// - implement fmt::Display
impl fmt::Display for EncryptedObjectFooterLogical {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::struct_name())
    }
}

impl HeaderCoding for EncryptedObjectFooterLogical {
    type Item = EncryptedObjectFooterLogical;
    fn version() -> u8 {
        DEFAULT_FOOTER_VERSION_OBJECT_FOOTER_LOGICAL
    }
    fn identifier() -> u32 {
        FOOTER_IDENTIFIER_OBJECT_FOOTER_LOGICAL
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
        Self::check_version(&mut cursor)?; // check version (and skip it)
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
