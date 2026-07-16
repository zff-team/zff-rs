// - STD
use std::collections::HashMap;
use std::fmt;
use std::io::{Cursor, Read};

// - internal
#[cfg(feature = "serde")]
use crate::helper::string_to_str;
use crate::prelude::*;

// - external
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct};

/// The description header contains all data that describes the dumped data in the appropriate object (e.g., case number, examiner name, or acquisition date).
///
/// The description information is stored in a HashMap (e.g., like ["acquisition tool", "zffacquire"]).
/// Some fields are predefined to ensure a certain degree of compatibility between different tools.
/// The following fields are predefined:
/// - case number (for the appropriate HashMap key, see [ENCODING_KEY_CASE_NUMBER](crate::constants::ENCODING_KEY_CASE_NUMBER))
/// - evidence number (for the appropriate HashMap key, see [ENCODING_KEY_EVIDENCE_NUMBER](crate::constants::ENCODING_KEY_EVIDENCE_NUMBER))
/// - examiner name (for the appropriate HashMap key, see [ENCODING_KEY_EXAMINER_NAME](crate::constants::ENCODING_KEY_EXAMINER_NAME))
/// - notes (for the appropriate HashMap key, see [ENCODING_KEY_NOTES](crate::constants::ENCODING_KEY_NOTES))
/// - tool name (for the appropriate HashMap key, see [ENCODING_KEY_TOOL_NAME](crate::constants::ENCODING_KEY_TOOL_NAME))
/// - tool version (for the appropriate HashMap key, see [ENCODING_KEY_TOOL_VERSION](crate::constants::ENCODING_KEY_TOOL_VERSION))
/// - logical sector size (for the appropriate HashMap key, see [ENCODING_KEY_LOGICAL_SECTOR_SIZE](crate::constants::ENCODING_KEY_LOGICAL_SECTOR_SIZE))
/// - physical sector size (for the appropriate HashMap key, see [ENCODING_KEY_PHYSICAL_SECTOR_SIZE](crate::constants::ENCODING_KEY_PHYSICAL_SECTOR_SIZE))
/// - model name/number (for the appropriate HashMap key, see [ENCODING_KEY_MODEL](crate::constants::ENCODING_KEY_MODEL))
/// - serial number (for the appropriate HashMap key, see [ENCODING_KEY_SERIAL_NUMBER](crate::constants::ENCODING_KEY_SERIAL_NUMBER))
/// - firmware version (for the appropriate HashMap key, see [ENCODING_KEY_FIRMWARE](crate::constants::ENCODING_KEY_FIRMWARE))
/// - media type (for the appropriate HashMap key, see [ENCODING_KEY_MEDIA_TYPE](crate::constants::ENCODING_KEY_MEDIA_TYPE))
/// - input source path (for the appropriate HashMap key, see [ENCODING_KEY_INPUT_SOURCE](crate::constants::ENCODING_KEY_INPUT_SOURCE))
/// - operating system/platform (for the appropriate HashMap key, see [ENCODING_KEY_OPERATING_SYSTEM](crate::constants::ENCODING_KEY_OPERATING_SYSTEM))
///
/// But you are free to define custom additional key-value pairs.
///
/// # Example
/// ```
/// use zff::header::DescriptionHeader;
///
/// let header_version = 2;
/// let mut description_header = DescriptionHeader::new_empty();
///
/// description_header.set_examiner_name("ph0llux");
/// assert_eq!(Some("ph0llux"), description_header.examiner_name());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
pub struct DescriptionHeader {
    /// The inner identifier map.
    pub identifier_map: HashMap<String, String>,
}

#[cfg(feature = "serde")]
impl Serialize for DescriptionHeader {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer
            .serialize_struct(Self::struct_name(), self.identifier_map.keys().len() + 1)?;
        state.serialize_field("version", &Self::version())?;
        for (key, value) in &self.identifier_map {
            state.serialize_field(
                string_to_str(key.to_string()),
                string_to_str(value.to_string()),
            )?;
        }
        state.end()
    }
}

impl DescriptionHeader {
    /// creates a new, empty header, which can be filled by the set_*-methods.
    /// All fields will be initialized with ```None``` or ```0```.
    pub fn new_empty() -> DescriptionHeader {
        Self {
            identifier_map: HashMap::new(),
        }
    }

    /// Creates a new [DescriptionHeader] with the given identifier map.
    pub fn new(identifier_map: HashMap<String, String>) -> DescriptionHeader {
        Self { identifier_map }
    }

    /// sets the case number as ```String```.
    pub fn set_case_number<V: Into<String>>(&mut self, value: V) {
        self.identifier_map
            .insert(String::from(ENCODING_KEY_CASE_NUMBER), value.into());
    }

    /// sets the evidence number as ```String```.
    pub fn set_evidence_number<V: Into<String>>(&mut self, value: V) {
        self.identifier_map
            .insert(String::from(ENCODING_KEY_EVIDENCE_NUMBER), value.into());
    }

    /// sets the examiner name as ```String```.
    pub fn set_examiner_name<V: Into<String>>(&mut self, value: V) {
        self.identifier_map
            .insert(String::from(ENCODING_KEY_EXAMINER_NAME), value.into());
    }

    /// sets some notes as ```String```.
    pub fn set_notes<V: Into<String>>(&mut self, value: V) {
        self.identifier_map
            .insert(String::from(ENCODING_KEY_NOTES), value.into());
    }

    /// returns the case number, if available.
    pub fn case_number(&self) -> Option<&str> {
        match &self.identifier_map.get(ENCODING_KEY_CASE_NUMBER) {
            Some(x) => Some(x),
            None => None,
        }
    }

    /// returns the evidence number, if available.
    pub fn evidence_number(&self) -> Option<&str> {
        match &self.identifier_map.get(ENCODING_KEY_EVIDENCE_NUMBER) {
            Some(x) => Some(x),
            None => None,
        }
    }

    /// returns the examiner name, if available.
    pub fn examiner_name(&self) -> Option<&str> {
        match &self.identifier_map.get(ENCODING_KEY_EXAMINER_NAME) {
            Some(x) => Some(x),
            None => None,
        }
    }

    /// returns the notes, if some available.
    pub fn notes(&self) -> Option<&str> {
        match &self.identifier_map.get(ENCODING_KEY_NOTES) {
            Some(x) => Some(x),
            None => None,
        }
    }

    /// sets the logical sector size of the source device.
    pub fn set_logical_sector_size<V: Into<String>>(&mut self, value: V) {
        self.identifier_map
            .insert(String::from(ENCODING_KEY_LOGICAL_SECTOR_SIZE), value.into());
    }

    /// returns the logical sector size of the source device, if available.
    pub fn logical_sector_size(&self) -> Option<&str> {
        match &self.identifier_map.get(ENCODING_KEY_LOGICAL_SECTOR_SIZE) {
            Some(x) => Some(x),
            None => None,
        }
    }

    /// sets the physical sector size of the source device.
    pub fn set_physical_sector_size<V: Into<String>>(&mut self, value: V) {
        self.identifier_map
            .insert(String::from(ENCODING_KEY_PHYSICAL_SECTOR_SIZE), value.into());
    }

    /// returns the physical sector size of the source device, if available.
    pub fn physical_sector_size(&self) -> Option<&str> {
        match &self.identifier_map.get(ENCODING_KEY_PHYSICAL_SECTOR_SIZE) {
            Some(x) => Some(x),
            None => None,
        }
    }

    /// sets the model name/number of the source device.
    pub fn set_model<V: Into<String>>(&mut self, value: V) {
        self.identifier_map
            .insert(String::from(ENCODING_KEY_MODEL), value.into());
    }

    /// returns the model name/number of the source device, if available.
    pub fn model(&self) -> Option<&str> {
        match &self.identifier_map.get(ENCODING_KEY_MODEL) {
            Some(x) => Some(x),
            None => None,
        }
    }

    /// sets the serial number of the source device.
    pub fn set_serial_number<V: Into<String>>(&mut self, value: V) {
        self.identifier_map
            .insert(String::from(ENCODING_KEY_SERIAL_NUMBER), value.into());
    }

    /// returns the serial number of the source device, if available.
    pub fn serial_number(&self) -> Option<&str> {
        match &self.identifier_map.get(ENCODING_KEY_SERIAL_NUMBER) {
            Some(x) => Some(x),
            None => None,
        }
    }

    /// sets the firmware version of the source device.
    pub fn set_firmware<V: Into<String>>(&mut self, value: V) {
        self.identifier_map
            .insert(String::from(ENCODING_KEY_FIRMWARE), value.into());
    }

    /// returns the firmware version of the source device, if available.
    pub fn firmware(&self) -> Option<&str> {
        match &self.identifier_map.get(ENCODING_KEY_FIRMWARE) {
            Some(x) => Some(x),
            None => None,
        }
    }

    /// sets the media type of the source device (e.g. "hdd", "ssd", "nvme", "usb", "sd", "emmc").
    pub fn set_media_type<V: Into<String>>(&mut self, value: V) {
        self.identifier_map
            .insert(String::from(ENCODING_KEY_MEDIA_TYPE), value.into());
    }

    /// returns the media type of the source device, if available.
    pub fn media_type(&self) -> Option<&str> {
        match &self.identifier_map.get(ENCODING_KEY_MEDIA_TYPE) {
            Some(x) => Some(x),
            None => None,
        }
    }

    /// sets the input source path of the acquired device (e.g. "/dev/sda").
    pub fn set_input_source<V: Into<String>>(&mut self, value: V) {
        self.identifier_map
            .insert(String::from(ENCODING_KEY_INPUT_SOURCE), value.into());
    }

    /// returns the input source path, if available.
    pub fn input_source(&self) -> Option<&str> {
        match &self.identifier_map.get(ENCODING_KEY_INPUT_SOURCE) {
            Some(x) => Some(x),
            None => None,
        }
    }

    /// sets the operating system/platform the acquisition tool ran on (e.g. "Linux 6.8.0-49-generic").
    pub fn set_operating_system<V: Into<String>>(&mut self, value: V) {
        self.identifier_map
            .insert(String::from(ENCODING_KEY_OPERATING_SYSTEM), value.into());
    }

    /// returns the operating system/platform, if available.
    pub fn operating_system(&self) -> Option<&str> {
        match &self.identifier_map.get(ENCODING_KEY_OPERATING_SYSTEM) {
            Some(x) => Some(x),
            None => None,
        }
    }

    /// inserts a custom key-value pair
    pub fn custom_identifier_value<K: Into<String>, V: Into<String>>(&mut self, key: K, value: V) {
        self.identifier_map.insert(key.into(), value.into());
    }

    /// returns all key-value pairs of this header.
    pub fn identifier_map(&self) -> &HashMap<String, String> {
        &self.identifier_map
    }
}

impl HeaderCoding for DescriptionHeader {
    type Item = DescriptionHeader;

    fn identifier() -> u32 {
        HEADER_IDENTIFIER_DESCRIPTION_HEADER
    }

    fn version() -> u8 {
        DEFAULT_HEADER_VERSION_DESCRIPTION_HEADER
    }

    fn encode_content(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.identifier_map.encode_directly());
        vec
    }

    /// decodes the header directly.
    fn decode_directly<R: Read>(data: &mut R) -> Result<Self::Item> {
        if !Self::check_identifier(data) {
            return Err(ZffError::new(
                ZffErrorKind::Invalid,
                ERROR_HEADER_DECODER_MISMATCH_IDENTIFIER,
            ));
        }
        let header_length = Self::decode_header_length(data)? as usize;
        let mut header_content = vec![
            0u8;
            header_length
                - DEFAULT_LENGTH_HEADER_IDENTIFIER
                - DEFAULT_LENGTH_VALUE_HEADER_LENGTH
        ];
        data.read_exact(&mut header_content)?;
        Self::decode_content(&header_content)
    }

    fn decode_content(data: &[u8]) -> Result<DescriptionHeader> {
        let mut cursor = Cursor::new(data);
        Self::check_version(&mut cursor)?;
        let identifier_map = HashMap::<String, String>::decode_directly(&mut cursor)?;
        let description_header = DescriptionHeader::new(identifier_map);

        Ok(description_header)
    }
}

impl fmt::Display for DescriptionHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::struct_name())
    }
}
