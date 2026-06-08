// - STD
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io::{Cursor, Read};

// - internal
use crate::prelude::*;

// - external
use byteorder::{LittleEndian, ReadBytesExt};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Holds the appropriate object flags:
/// - the encryption flag, if the appropriate object is encrypted.
/// - the sign hash flag, if the appropriate calculated hash value was signed.
/// - the passive object flag, if this object should not handled as an active object
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ObjectFlags {
    /// this flag is set if the object is encrypted.
    pub encryption: bool,
    /// this flag is set, if signatures are available for this object.
    pub sign_hash: bool,
    /// this object is a "passive only" object and should be interpreted by a higher leveled virtual object
    pub passive_object: bool,
}

impl ObjectFlags {
    fn to_u8(&self) -> u8 {
        let mut flags = 0u8;

        if self.encryption {
            flags |= ENCRYPT_OBJECT_FLAG_VALUE;
        }

        if self.sign_hash {
            flags |= SIGN_HASH_FLAG_VALUE;
        }

        if self.passive_object {
            flags |= PASSIVE_OBJECT_FLAG;
        }

        flags
    }
}

impl From<u8> for ObjectFlags {
    fn from(flag_values: u8) -> Self {
        Self {
            encryption: flag_values & ENCRYPT_OBJECT_FLAG_VALUE != 0,
            sign_hash: flag_values & SIGN_HASH_FLAG_VALUE != 0,
            passive_object: flag_values & PASSIVE_OBJECT_FLAG != 0,
        }
    }
}

impl From<ObjectFlags> for u8 {
    fn from(flags: ObjectFlags) -> Self {
        flags.to_u8()
    }
}

impl From<&ObjectFlags> for u8 {
    fn from(flags: &ObjectFlags) -> Self {
        flags.to_u8()
    }
}

/// Each object starts with a [ObjectHeader]. The [ObjectHeader] contains several metadata of the appropriate underlying object.
/// The following metadata are stored in an [ObjectHeader]:
/// - The appropriate number of the objects (the first object always starts with 1)
/// - An [crate::header::EncryptionHeader], if an encryption was used.
/// - A [crate::header::CompressionHeader], containing the appropriate compression information
/// - A [crate::header::DescriptionHeader] for this object.
/// - The [ObjectType] of this object.
/// - the appropriate [object flags](ObjectFlags).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ObjectHeader {
    /// the appropriate object number.
    pub object_number: u64,
    /// the appropriate [ObjectFlags].
    pub flags: ObjectFlags,
    /// the [EncryptionHeader], if available.
    pub encryption_header: Option<EncryptionHeader>,
    /// the target chunk size for chunks of this object.
    pub chunk_size: u64,
    /// the [crate::header::CompressionHeader], containing all information about the used compression method for this object.
    pub compression_header: CompressionHeader,
    /// the [crate::header::DescriptionHeader], containing some information about this object.
    pub description_header: DescriptionHeader,
    /// the appropriate [ObjectType].
    pub object_type: ObjectType,
}

/// For security purposes, the Drop implementation zeroize the underlying [EncryptionHeader] (which potentially contains
/// the decrypted encryption key).
impl Drop for ObjectHeader {
    fn drop(&mut self) {
        self.encryption_header.zeroize();
    }
}

impl ObjectHeader {
    /// creates a new object with the given values.
    pub fn new(
        object_number: u64,
        encryption_header: Option<EncryptionHeader>,
        chunk_size: u64,
        compression_header: CompressionHeader,
        description_header: DescriptionHeader,
        object_type: ObjectType,
        flags: ObjectFlags,
    ) -> ObjectHeader {
        Self {
            object_number,
            encryption_header,
            chunk_size,
            compression_header,
            description_header,
            object_type,
            flags,
        }
    }

    /// checks if a signature method was used. Returns true if and false if not.
    pub fn has_hash_signatures(&self) -> bool {
        self.flags.sign_hash
    }

    /// decodes the encrypted header with the given password at given offset.
    pub fn decode_at_encrypted_header_with_password<R, P>(
        data: &R,
        offset: u64,
        password: P,
    ) -> Result<ObjectHeader>
    where
        R: ReadAt + ?Sized,
        P: AsRef<[u8]>,
    {
        let mut cursor = ReadAtCursor::new(data, offset);
        Self::decode_encrypted_header_with_password(&mut cursor, password)
    }

    /// decodes the encrypted header with the given password.
    pub fn decode_encrypted_header_with_password<R, P>(
        data: &mut R,
        password: P,
    ) -> Result<ObjectHeader>
    where
        R: Read,
        P: AsRef<[u8]>,
    {
        if !Self::check_identifier(data) {
            return Err(ZffError::new(
                ZffErrorKind::Invalid,
                ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER,
            ));
        };
        let header_length = Self::decode_header_length(data)? as usize;
        let mut header_content = vec![
            0u8;
            header_length
                - DEFAULT_LENGTH_HEADER_IDENTIFIER
                - DEFAULT_LENGTH_VALUE_HEADER_LENGTH
        ];
        data.read_exact(&mut header_content)?;
        let mut cursor = Cursor::new(header_content);
        Self::check_version(&mut cursor)?;
        let object_number = u64::decode_directly(&mut cursor)?;
        let flags = ObjectFlags::from(u8::decode_directly(&mut cursor)?);
        if !flags.encryption {
            return Err(ZffError::new(
                ZffErrorKind::EncryptionError,
                ERROR_MISSING_ENCRYPTION_HEADER_KEY,
            ));
        }
        let mut encryption_header = EncryptionHeader::decode_directly(&mut cursor)?;
        let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
        let encryption_key = encryption_header.decrypt_encryption_key(password)?;
        let algorithm = &encryption_header.algorithm;
        let decrypted_data =
            Self::decrypt(encryption_key, encrypted_data, object_number, algorithm)?;
        let mut cursor = Cursor::new(decrypted_data);
        let (chunk_size, compression_header, description_header, object_type) =
            Self::decode_inner_content(&mut cursor)?;
        let object_header = Self::new(
            object_number,
            Some(encryption_header),
            chunk_size,
            compression_header,
            description_header,
            object_type,
            flags,
        );
        Ok(object_header)
    }

    fn decode_inner_content<R: Read>(
        inner_content: &mut R,
    ) -> Result<(
        u64, //chunk size
        CompressionHeader,
        DescriptionHeader,
        ObjectType,
    )> {
        let chunk_size = u64::decode_directly(inner_content)?;
        let compression_header = CompressionHeader::decode_directly(inner_content)?;
        let description_header = DescriptionHeader::decode_directly(inner_content)?;
        let object_type = match u8::decode_directly(inner_content)? {
            0 => ObjectType::Physical,
            1 => ObjectType::Logical,
            2 => ObjectType::Virtual,
            value => {
                return Err(ZffError::new(
                    ZffErrorKind::Invalid,
                    format!("{ERROR_INVALID_TYPE_FLAG_VALUE}{value}"),
                ));
            }
        };
        let inner_content = (
            chunk_size,
            compression_header,
            description_header,
            object_type,
        );
        Ok(inner_content)
    }
}

impl HeaderEncryption for ObjectHeader {
    fn encryption_precondition(&self) -> bool {
        self.encryption_header.is_some()
    }

    fn nonce_value(&self) -> u64 {
        self.object_number
    }
}

impl Encryption for ObjectHeader {
    fn crypto_nonce_padding() -> u8 {
        CRYPTO_NONCE_PADDING_OBJECT_HEADER
    }
}

// - implement fmt::Display
impl fmt::Display for ObjectHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::struct_name())
    }
}

impl HeaderCoding for ObjectHeader {
    type Item = ObjectHeader;

    fn identifier() -> u32 {
        HEADER_IDENTIFIER_OBJECT_HEADER
    }

    fn version() -> u8 {
        DEFAULT_HEADER_VERSION_OBJECT_HEADER
    }

    fn encode_content(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.chunk_size.encode_directly());
        vec.extend_from_slice(&self.compression_header.encode_directly());
        vec.extend_from_slice(&self.description_header.encode_directly());
        vec.extend_from_slice(&(self.object_type.clone() as u8).encode_directly());
        vec
    }

    fn encode_fixed_fields(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.object_number.encode_directly());
        vec.extend_from_slice(&u8::from(&self.flags).encode_directly());
        if let Some(encryption_header) = &self.encryption_header {
            vec.extend_from_slice(&encryption_header.encode_directly())
        };
        vec
    }

    fn decode_content(data: &[u8]) -> Result<ObjectHeader> {
        let mut cursor = Cursor::new(data);
        Self::check_version(&mut cursor)?;
        let object_number = u64::decode_directly(&mut cursor)?;
        let flags = ObjectFlags::from(u8::decode_directly(&mut cursor)?);
        if flags.encryption {
            return Err(ZffError::new(
                ZffErrorKind::EncryptionError,
                ERROR_MISSING_ENCRYPTION_HEADER_KEY,
            ));
        }
        let (chunk_size, compression_header, description_header, object_type) =
            Self::decode_inner_content(&mut cursor)?;

        let object_header = Self::new(
            object_number,
            None,
            chunk_size,
            compression_header,
            description_header,
            object_type,
            flags,
        );
        Ok(object_header)
    }
}

impl PartialEq for ObjectHeader {
    fn eq(&self, other: &Self) -> bool {
        self.object_number == other.object_number
    }
}

impl Eq for ObjectHeader {}

impl Hash for ObjectHeader {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.object_number.hash(state);
    }
}

/// Defines the [ObjectType], which can be used in zff container.
#[repr(u8)]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum ObjectType {
    /// An object containing a physical dump.
    Physical = 0,
    /// An object, containing logical files.
    Logical = 1,
    /// A virtual object.
    Virtual = 2,
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            ObjectType::Physical => "Physical",
            ObjectType::Logical => "Logical",
            ObjectType::Virtual => "Virtual",
        };
        write!(f, "{}", msg)
    }
}

/// The [EncryptedObjectHeader] represents (as the name suggests) an encrypted object header.
///
/// An [EncryptedObjectHeader] contains the appropriate object number, the [ObjectFlags],
/// the [crate::header::EncryptionHeader] and
/// the encrypted blob containing the other header values (in encrypted form).
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct EncryptedObjectHeader {
    /// the appropriate object number.
    pub object_number: u64,
    /// the object flags.
    pub flags: ObjectFlags,
    /// the [crate::header::EncryptionHeader].
    pub encryption_header: EncryptionHeader,
    /// the encrypted blob with the other header values.
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "crate::helper::buffer_to_hex",
            deserialize_with = "crate::helper::hex_to_buffer"
        )
    )]
    pub encrypted_content: Vec<u8>,
}

impl EncryptedObjectHeader {
    /// creates a new encrypted object header with the given values.
    pub fn new(
        object_number: u64,
        flags: ObjectFlags,
        encryption_header: EncryptionHeader,
        encrypted_content: Vec<u8>,
    ) -> Self {
        Self {
            object_number,
            flags,
            encryption_header,
            encrypted_content,
        }
    }

    /// Decodes the length of the header.
    pub fn decode_header_length<R: Read>(data: &mut R) -> Result<u64> {
        match data.read_u64::<LittleEndian>() {
            Ok(value) => Ok(value),
            Err(_) => Err(ZffError::new(
                ZffErrorKind::Invalid,
                ERROR_HEADER_DECODER_HEADER_LENGTH,
            )),
        }
    }

    /// Decodes the encrypted header with the given password.
    pub fn decrypt_with_password<P>(&mut self, password: P) -> Result<ObjectHeader>
    where
        P: AsRef<[u8]>,
    {
        let encryption_key = self.encryption_header.decrypt_encryption_key(password)?;
        let algorithm = &self.encryption_header.algorithm;
        let decrypted_data = Self::decrypt(
            encryption_key,
            &self.encrypted_content,
            self.object_number,
            algorithm,
        )?;
        let mut cursor = Cursor::new(decrypted_data);
        let (chunk_size, compression_header, description_header, object_type) =
            ObjectHeader::decode_inner_content(&mut cursor)?;
        let object_header = ObjectHeader::new(
            self.object_number,
            Some(self.encryption_header.clone()),
            chunk_size,
            compression_header,
            description_header,
            object_type,
            self.flags.clone(),
        );
        Ok(object_header)
    }

    /// Tries to decrypt the ObjectHeader. Consumes the EncryptedObjectHeader, regardless of whether an error occurs or not.
    pub fn decrypt_and_consume_with_password<P>(mut self, password: P) -> Result<ObjectHeader>
    where
        P: AsRef<[u8]>,
    {
        self.decrypt_with_password(password)
    }
}

impl HeaderCoding for EncryptedObjectHeader {
    type Item = Self;

    fn identifier() -> u32 {
        HEADER_IDENTIFIER_OBJECT_HEADER
    }

    fn version() -> u8 {
        DEFAULT_HEADER_VERSION_OBJECT_HEADER
    }

    fn encode_content(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.object_number.encode_directly());
        vec.extend_from_slice(&u8::from(&self.flags).encode_directly());
        vec.extend_from_slice(&self.encryption_header.encode_directly());
        vec.extend_from_slice(&self.encrypted_content.encode_directly());
        vec
    }

    fn decode_content(data: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(data);
        let header_version = u8::decode_directly(&mut cursor)?;
        if header_version != DEFAULT_HEADER_VERSION_OBJECT_HEADER {
            return Err(ZffError::new(
                ZffErrorKind::Unsupported,
                format!("{ERROR_UNSUPPORTED_VERSION}{header_version}"),
            ));
        };
        let object_number = u64::decode_directly(&mut cursor)?;
        let flags = ObjectFlags::from(u8::decode_directly(&mut cursor)?);
        if !flags.encryption {
            return Err(ZffError::new(ZffErrorKind::EncodingError, ""));
        }
        let encryption_header = EncryptionHeader::decode_directly(&mut cursor)?;
        let encrypted_data = Vec::<u8>::decode_directly(&mut cursor)?;
        Ok(Self::new(
            object_number,
            flags,
            encryption_header,
            encrypted_data,
        ))
    }
}

impl Encryption for EncryptedObjectHeader {
    fn crypto_nonce_padding() -> u8 {
        CRYPTO_NONCE_PADDING_OBJECT_HEADER
    }
}
