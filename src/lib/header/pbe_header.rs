// - STD
use std::fmt;
use std::io::{Cursor, Read};

// - internal
use crate::helper::decode_len;
use crate::prelude::*;

// - external
use byteorder::{BigEndian, ReadBytesExt};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// The PBE header contains all information for encrypting the encryption key.
///
/// The encryption key, used for the chunk encryption, can be found at the [EncryptionHeader](struct.EncryptionHeader.html) -
/// encrypted with an user password.\
/// This encryption of the encryption key is done via a password-based encryption (PBE).\
/// All metadata about this PBE can be found in this PBEHeader.\
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct PBEHeader {
    /// The kdf scheme used for the encryption key derivation.
    pub kdf_scheme: KDFScheme,
    /// The encryption scheme used for the encryption key derivation.
    pub encryption_scheme: PBEScheme,
    /// The kdf parameters.
    pub kdf_parameters: KDFParameters,
    /// The nonce used for the encryption of the encryption key.
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "crate::helper::buffer_to_hex")
    )]
    pub pbencryption_nonce: [u8; 16],
}

impl PBEHeader {
    /// returns a new pbe header with the given values.
    pub fn new(
        kdf_scheme: KDFScheme,
        encryption_scheme: PBEScheme,
        kdf_parameters: KDFParameters,
        pbencryption_nonce: [u8; 16],
    ) -> PBEHeader {
        Self {
            kdf_scheme,
            encryption_scheme,
            kdf_parameters,
            pbencryption_nonce,
        }
    }
}

impl HeaderCoding for PBEHeader {
    type Item = Self;

    fn identifier() -> u32 {
        HEADER_IDENTIFIER_PBE_HEADER
    }

    fn version() -> u8 {
        DEFAULT_HEADER_VERSION_PBE_HEADER
    }

    fn encode_content(&self) -> Vec<u8> {
        let mut vec = vec![
            self.kdf_scheme.clone() as u8,
            self.encryption_scheme.clone() as u8,
        ];
        vec.extend_from_slice(&self.kdf_parameters.encode_directly());
        vec.extend_from_slice(&self.pbencryption_nonce.encode_directly());
        vec
    }

    fn decode_content(data: &[u8]) -> Result<PBEHeader> {
        let mut cursor = Cursor::new(data);
        Self::check_version(&mut cursor)?;
        let kdf_scheme = match u8::decode_directly(&mut cursor)? {
            0 => KDFScheme::PBKDF2SHA256,
            1 => KDFScheme::Scrypt,
            2 => KDFScheme::Argon2id,
            _ => {
                return Err(ZffError::new(
                    ZffErrorKind::Invalid,
                    ERROR_HEADER_DECODER_UNKNOWN_KDF_SCHEME,
                ));
            }
        };
        let encryption_scheme = match u8::decode_directly(&mut cursor)? {
            0 => PBEScheme::AES128CBC,
            1 => PBEScheme::AES256CBC,
            _ => {
                return Err(ZffError::new(
                    ZffErrorKind::Invalid,
                    ERROR_HEADER_DECODER_UNKNOWN_PBE_SCHEME,
                ));
            }
        };
        let kdf_params = KDFParameters::decode_directly(&mut cursor)?;
        let mut encryption_nonce = [0; 16];
        cursor.read_exact(&mut encryption_nonce)?;
        Ok(PBEHeader::new(
            kdf_scheme,
            encryption_scheme,
            kdf_params,
            encryption_nonce,
        ))
    }
}

// - implement fmt::Display
impl fmt::Display for PBEHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::struct_name())
    }
}

/// Enum containing the parameters for the appropriate key derivation function (KDF).
///
/// This enum wraps the specific parameter types for different KDF schemes used in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug, Clone, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum KDFParameters {
    /// stores a struct [PBKDF2SHA256Parameters].
    PBKDF2SHA256Parameters(PBKDF2SHA256Parameters),
    /// stores a struct [ScryptParameters].
    ScryptParameters(ScryptParameters),
    /// stores a struct [Argon2idParameters].
    Argon2idParameters(Argon2idParameters),
}

impl ValueEncoder for KDFParameters {
    fn encode_directly(&self) -> Vec<u8> {
        match self {
            KDFParameters::PBKDF2SHA256Parameters(params) => params.encode_directly(),
            KDFParameters::ScryptParameters(params) => params.encode_directly(),
            KDFParameters::Argon2idParameters(params) => params.encode_directly(),
        }
    }

    fn identifier(&self) -> u8 {
        METADATA_EXT_TYPE_IDENTIFIER_UNKNOWN
    }

    fn encoded_size(&self) -> usize {
        match self {
            KDFParameters::PBKDF2SHA256Parameters(params) => params.header_size(),
            KDFParameters::ScryptParameters(params) => params.header_size(),
            KDFParameters::Argon2idParameters(params) => params.header_size(),
        }
    }
}

impl ValueDecoder for KDFParameters {
    type Item = KDFParameters;

    fn decode_directly<R: Read>(data: &mut R) -> Result<KDFParameters> {
        let identifier = data.read_u32::<BigEndian>()?;
        let size = decode_len(data)?;
        let params_len = size
            .checked_sub(DEFAULT_LENGTH_HEADER_IDENTIFIER + DEFAULT_LENGTH_VALUE_HEADER_LENGTH)
            .ok_or_else(|| ZffError::new(ZffErrorKind::EncodingError, ERROR_MALFORMED_SEGMENT))?;
        let mut params = Vec::new();
        params.try_reserve_exact(params_len)?;
        params.resize(params_len, 0);
        data.read_exact(&mut params)?;

        let mut params_cursor = Cursor::new(params);

        if identifier == PBKDF2SHA256Parameters::identifier() {
            let iterations = u32::decode_directly(&mut params_cursor)?;
            let mut salt = [0; 32];
            params_cursor.read_exact(&mut salt)?;
            let parameters = PBKDF2SHA256Parameters::new(iterations, salt);
            Ok(KDFParameters::PBKDF2SHA256Parameters(parameters))
        } else if identifier == ScryptParameters::identifier() {
            let logn = u8::decode_directly(&mut params_cursor)?;
            let r = u32::decode_directly(&mut params_cursor)?;
            let p = u32::decode_directly(&mut params_cursor)?;
            let mut salt = [0; 32];
            params_cursor.read_exact(&mut salt)?;
            let parameters = ScryptParameters::new(logn, r, p, salt);
            Ok(KDFParameters::ScryptParameters(parameters))
        } else if identifier == Argon2idParameters::identifier() {
            let mem_cost = u32::decode_directly(&mut params_cursor)?;
            let lanes = u32::decode_directly(&mut params_cursor)?;
            let iterations = u32::decode_directly(&mut params_cursor)?;
            let mut salt = [0; 32];
            params_cursor.read_exact(&mut salt)?;
            let parameters = Argon2idParameters::new(mem_cost, lanes, iterations, salt);
            Ok(KDFParameters::Argon2idParameters(parameters))
        } else {
            Err(ZffError::new(
                ZffErrorKind::Invalid,
                ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER_KDF,
            ))
        }
    }
}

/// Parameters for the PBKDF2-SHA256 key derivation function.
///
/// PBKDF2 (Password-Based Key Derivation Function 2) applies a pseudorandom function,
/// such as a cryptographic hash, cipher, or HMAC to the input password along with a salt
/// and repeats the process many times to produce a derived key.
#[derive(Debug, Clone, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct PBKDF2SHA256Parameters {
    /// The iterations to use.
    pub iterations: u32,
    /// The salt value.
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "crate::helper::buffer_to_hex")
    )]
    pub salt: [u8; 32],
}

impl PBKDF2SHA256Parameters {
    /// returns a new [PBKDF2SHA256Parameters] with the given values.
    pub fn new(iterations: u32, salt: [u8; 32]) -> PBKDF2SHA256Parameters {
        Self { iterations, salt }
    }
}

impl HeaderCoding for PBKDF2SHA256Parameters {
    type Item = Self;

    fn identifier() -> u32 {
        PBE_KDF_PARAMETERS_PBKDF2
    }

    /// just a placeholder, because this structure is not a header, but only a part of another header.
    fn version() -> u8 {
        0
    }

    // self implementation is necessary, this structure doesn't hold a version tag.
    fn encode_header(&self) -> Vec<u8> {
        self.encode_content()
    }

    fn encode_content(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.iterations.encode_directly());
        vec.extend_from_slice(&self.salt.encode_directly());
        vec
    }

    fn decode_content(data: &[u8]) -> Result<PBKDF2SHA256Parameters> {
        let mut cursor = Cursor::new(data);

        let iterations = u32::decode_directly(&mut cursor)?;
        let mut salt = [0; 32];
        cursor.read_exact(&mut salt)?;
        let parameters = PBKDF2SHA256Parameters::new(iterations, salt);
        Ok(parameters)
    }
}

/// Parameters for the Scrypt key derivation function.
///
/// Scrypt is a password-based key derivation function designed to be computationally
/// intensive to resist brute-force attacks.
#[derive(Debug, Clone, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ScryptParameters {
    /// The log n parameter for Scrypt.
    pub logn: u8,
    /// The r parameter for Scrypt.
    pub r: u32,
    /// The p parameter for Scrypt.
    pub p: u32,
    /// The used salt.
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "crate::helper::buffer_to_hex")
    )]
    pub salt: [u8; 32],
}

impl ScryptParameters {
    /// returns a new [ScryptParameters] with the given values.
    pub fn new(logn: u8, r: u32, p: u32, salt: [u8; 32]) -> ScryptParameters {
        Self { logn, r, p, salt }
    }
}

impl HeaderCoding for ScryptParameters {
    type Item = Self;

    fn identifier() -> u32 {
        PBE_KDF_PARAMETERS_SCRYPT
    }

    /// just a placeholder, because this structure is not a header, but only a part of another header.
    fn version() -> u8 {
        0
    }

    // self implementation is necessary, this structure doesn't hold a version tag.
    fn encode_content(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.logn.encode_directly());
        vec.extend_from_slice(&self.r.encode_directly());
        vec.extend_from_slice(&self.p.encode_directly());
        vec.extend_from_slice(&self.salt.encode_directly());
        vec
    }

    fn encode_header(&self) -> Vec<u8> {
        self.encode_content()
    }

    fn decode_content(data: &[u8]) -> Result<ScryptParameters> {
        let mut cursor = Cursor::new(data);

        let logn = u8::decode_directly(&mut cursor)?;
        let r = u32::decode_directly(&mut cursor)?;
        let p = u32::decode_directly(&mut cursor)?;
        let mut salt = [0; 32];
        cursor.read_exact(&mut salt)?;
        let parameters = ScryptParameters::new(logn, r, p, salt);
        Ok(parameters)
    }
}

/// Parameters for the Argon2id key derivation function.
///
/// Argon2id is a memory-hard password hashing function that won the Password Hashing
/// Competition. It provides configurable memory, CPU, and parallelism parameters.
#[derive(Debug, Clone, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct Argon2idParameters {
    /// The memory cost parameter for Argon2id (in KiB).
    pub mem_cost: u32,
    /// The number of lanes (threads) for Argon2id.
    pub lanes: u32,
    /// The number of iterations for Argon2id.
    pub iterations: u32,
    /// The salt used for key derivation.
    pub salt: [u8; 32],
}

impl Argon2idParameters {
    /// Returns a new [Argon2idParameters] with the given values.
    pub fn new(mem_cost: u32, lanes: u32, iterations: u32, salt: [u8; 32]) -> Argon2idParameters {
        Self {
            mem_cost,
            lanes,
            iterations,
            salt,
        }
    }
}

impl HeaderCoding for Argon2idParameters {
    type Item = Self;

    fn identifier() -> u32 {
        PBE_KDF_PARAMETERS_ARGON2ID
    }

    /// just a placeholder, because this structure is not a header, but only a part of another header.
    fn version() -> u8 {
        0
    }

    // self implementation is necessary, this structure doesn't hold a version tag.
    fn encode_header(&self) -> Vec<u8> {
        self.encode_content()
    }

    fn encode_content(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.mem_cost.encode_directly());
        vec.extend_from_slice(&self.lanes.encode_directly());
        vec.extend_from_slice(&self.iterations.encode_directly());
        vec.extend_from_slice(&self.salt.encode_directly());
        vec
    }

    fn decode_content(data: &[u8]) -> Result<Argon2idParameters> {
        let mut cursor = Cursor::new(data);
        let mem_cost = u32::decode_directly(&mut cursor)?;
        let lanes = u32::decode_directly(&mut cursor)?;
        let iterations = u32::decode_directly(&mut cursor)?;
        let mut salt = [0; 32];
        cursor.read_exact(&mut salt)?;
        let parameters = Argon2idParameters::new(mem_cost, lanes, iterations, salt);
        Ok(parameters)
    }
}
