// - Parent
use super::*;


/// Represents a platform-native string in an interoperable on-disk form.
///
/// This type is intended for forensic preservation of path-bearing values such
/// as file names or symlink targets. In contrast to [`String`], it does not
/// require UTF-8 and preserves the original encoded bytes exactly.
///
/// Encoding variants:
/// - [`PlatformString::Unix`]: raw Unix pathname bytes
/// - [`PlatformString::WindowsUtf16Le`]: raw bytes interpreted as UTF-16 little-endian
///
/// The stored bytes are preserved exactly during encoding/decoding, even if they
/// are malformed for the declared encoding. Validation is only performed by
/// explicit conversion helpers such as [`PlatformString::to_string_strict`].
///
/// # Serde behavior
///
/// When the `serde` feature is enabled, `PlatformString` values that are
/// serialized through higher-level structures may be emitted in a lossy,
/// human-readable form. This is intentional:
///
/// - binary zff encoding/decoding remains lossless
/// - serde output is intended for display/export formats such as JSON or TOML
/// - serde serialization must not be relied upon for forensic preservation
///
/// In other words:
/// - [`ValueEncoder`] / [`ValueDecoder`]: exact byte-preserving representation
/// - [`serde::Serialize`]: human-readable representation, potentially lossy
///
/// # Display behavior
///
/// [`Display`](fmt::Display) uses a lossy conversion and is intended only for
/// human-readable output, not for forensic round-tripping.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PlatformString {
    /// Raw bytes interpreted as UTF-8
    Unix(Vec<u8>),
    /// Raw bytes interpreted as UTF-16 little-endian.
    WindowsUtf16Le(Vec<u8>),
}

impl PlatformString {
    /// Byte representation of the appropriate [PlatformString].
    /// Does not contain the encoding information.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Unix(bytes) | Self::WindowsUtf16Le(bytes) => bytes,
        }
    }

    /// Byte representation of the appropriate [PlatformString].
    /// Does not contain the encoding information.
    pub fn into_bytes(self) -> Vec<u8> {
        match self {
            Self::Unix(bytes) | Self::WindowsUtf16Le(bytes) => bytes,
        }
    }

    /// Ensures that the Result is a UTF-8 valid string.
    /// Fails if the string does contain invalid UTF-8 characters.
    pub fn to_string_strict(&self) -> Result<String> {
        match self {
            Self::Unix(bytes) => String::from_utf8(bytes.clone()).map_err(|e| {
                ZffError::new_with_source(ZffErrorKind::EncodingError, Some(Box::new(e)), "Invalid UTF-8")
            }),
            Self::WindowsUtf16Le(bytes) => {
                if bytes.len() % 2 != 0 {
                    return Err(ZffError::new(ZffErrorKind::EncodingError, "Odd number of bytes for UTF-16LE"));
                }
                let u16s = bytes
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect::<Vec<_>>();
                String::from_utf16(&u16s).map_err(|e| {
                    ZffError::new_with_source(ZffErrorKind::EncodingError, Some(Box::new(e)), "Invalid UTF-16LE")
                })
            }
        }
    }

    /// Lossy conversation to [String]. Note: This conversion is 
    /// lossy and only intended only for human-readable output, not 
    /// for forensic round-tripping.
    pub fn to_string_lossy(&self) -> String {
        match self {
            Self::Unix(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            Self::WindowsUtf16Le(bytes) => {
                if bytes.len() % 2 != 0 {
                    return String::from_utf8_lossy(bytes).into_owned();
                }
                let u16s = bytes
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect::<Vec<_>>();
                String::from_utf16_lossy(&u16s)
            }
        }
    }
}

impl fmt::Display for PlatformString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_lossy())
    }
}

#[cfg(feature = "serde")]
impl Serialize for PlatformString {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string_lossy())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for PlatformString {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|value| Self::from(OsString::from(value)))
    }
}

#[cfg(target_family = "unix")]
impl From<&OsStr> for PlatformString {
    fn from(value: &OsStr) -> Self {
        Self::Unix(value.to_os_string().into_vec())
    }
}

#[cfg(target_family = "unix")]
impl From<OsString> for PlatformString {
    fn from(value: OsString) -> Self {
        Self::Unix(value.into_vec())
    }
}

#[cfg(target_os = "windows")]
impl From<&OsStr> for PlatformString {
    fn from(value: &OsStr) -> Self {
        let bytes = value
            .encode_wide()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>();
        Self::WindowsUtf16Le(bytes)
    }
}

#[cfg(target_family = "unix")]
impl TryFrom<&PlatformString> for OsString {
    type Error = ZffError;

    fn try_from(value: &PlatformString) -> Result<Self> {
        match value {
            PlatformString::Unix(bytes) => Ok(OsString::from_vec(bytes.clone())),
            PlatformString::WindowsUtf16Le(_) => Err(ZffError::new(
                ZffErrorKind::EncodingError,
                "UTF-16LE PlatformString cannot be converted to Unix OsString directly",
            )),
        }
    }
}

#[cfg(target_os = "windows")]
impl From<std::ffi::OsString> for PlatformString {
    fn from(value: std::ffi::OsString) -> Self {
        let bytes = value
            .encode_wide()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>();
        Self::WindowsUtf16Le(bytes)
    }
}

impl ValueEncoder for PlatformString {
    fn encode_directly(&self) -> Vec<u8> {
        let mut vec = Vec::new();

        let (encoding_flag, bytes) = match self {
            PlatformString::Unix(bytes) => (0u8, bytes),
            PlatformString::WindowsUtf16Le(bytes) => (1u8, bytes),
        };

        vec.push(encoding_flag);
        vec.append(&mut (bytes.len() as u64).encode_directly());
        vec.extend_from_slice(bytes);

        vec
    }

    fn identifier(&self) -> u8 {
        METADATA_EXT_TYPE_IDENTIFIER_PLATFORM_STRING
    }
}

impl ValueDecoder for PlatformString {
    type Item = PlatformString;

    fn decode_directly<R: Read>(data: &mut R) -> Result<Self::Item> {
        let encoding_flag = u8::decode_directly(data)?;
        let length = u64::decode_directly(data)? as usize;
        let mut buffer = vec![0u8; length];
        data.read_exact(&mut buffer)?;

        match encoding_flag {
            0 => Ok(PlatformString::Unix(buffer)),
            1 => Ok(PlatformString::WindowsUtf16Le(buffer)),
            value => Err(ZffError::new(
                ZffErrorKind::EncodingError,
                format!("Unknown PlatformString encoding flag: {value}"),
            )),
        }
    }
}
