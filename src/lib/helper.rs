// STD
use std::collections::{BTreeMap, BTreeSet};

// internal
use crate::{Result, ZffError, ZffErrorKind};

// external
#[cfg(feature = "log")]
use log::debug;
#[cfg(feature = "serde")]
use hex::FromHex;
#[cfg(feature = "serde")]
use base64::{Engine, engine::general_purpose::STANDARD as base64engine};
#[cfg(feature = "serde")]
use serde::Deserialize;

#[cfg(feature = "serde")]
pub(crate) fn string_to_str(s: String) -> &'static str {
  Box::leak(s.into_boxed_str())
}

#[cfg(feature = "serde")]
pub(crate) fn as_hex<S>(x: &u64, s: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_str(&format!("0x{:X}", x))
}

pub(crate) fn find_vmi_offset(offset_maps: &BTreeSet<BTreeMap<u64, (u64, u64)>>, offset: u64) -> Option<(u64, u64)> {
    let set_index = binary_search_for_map_in_set(offset_maps, offset).ok()?;
    let map = offset_maps.iter().nth(set_index)?;
    let (_, (segment_no, offset)) = map.range(..=offset).next_back()?;
    Some((*segment_no, *offset))
}

fn binary_search_for_map_in_set(set: &BTreeSet<BTreeMap<u64, (u64, u64)>>, offset: u64) -> Result<usize> {
    // The zombie counter is used to prevent infinite loops (if the set is malformed, etc.)
    let mut zombie_counter = 0;
    let mut low = 0;
    let mut high = set.len() - 1;
    while low <= high {
        if zombie_counter > 1000 {
            #[cfg(feature = "log")]
            debug!("Malformed VMI map. Exiting.");
            return Err(ZffError::new(ZffErrorKind::BinarySearchError, "zombie counter exceeded 1000 iterations. Exiting."));
        }
        let mid = (low + high) / 2;
        let lowest_offset = set.iter().nth(mid).unwrap().keys().next().unwrap();
        let highest_offset = set.iter().nth(mid).unwrap().keys().next_back().unwrap();
        if lowest_offset <= &offset && highest_offset >= &offset {
            // returns the appropriate set index
            return Ok(mid);
        } else if lowest_offset > &offset {
            // search left
            high = mid - 1;
            zombie_counter += 1;
        } else {
            // search right
            low = mid + 1;
            zombie_counter += 1;
        }
    }
    #[cfg(feature = "log")]
    debug!("Empty map");
    Err(ZffError::new(ZffErrorKind::BinarySearchError, "Empty map"))
}


#[cfg(feature = "serde")]
/// Serializes `buffer` to a lowercase hex string.
pub fn buffer_to_hex<T, S>(buffer: &T, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where T: AsRef<[u8]>,
        S: serde::Serializer
{
  serializer.serialize_str(&hex::encode(&buffer))
}

#[cfg(feature = "serde")]
/// Deserializes a lowercase hex string to a `Vec<u8>`.
pub fn hex_to_buffer<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
  where D: serde::Deserializer<'de>
{
  use serde::de::Error;
  String::deserialize(deserializer)
    .and_then(|string| Vec::from_hex(&string).map_err(|err| Error::custom(err.to_string())))
}

#[cfg(feature = "serde")]
/// Serializes `buffer` to a lowercase base64 string.
pub fn buffer_to_base64<T, S>(buffer: &T, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where T: AsRef<[u8]>,
        S: serde::Serializer
{
  serializer.serialize_str(&base64engine.encode(&buffer))
}

#[cfg(feature = "serde")]
/// Deserializes a lowercase base64 string to a `Vec<u8>`.
pub fn base64_to_buffer<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
  where D: serde::Deserializer<'de>
{
  use serde::de::Error;
  String::deserialize(deserializer).and_then(|string| base64engine.decode(&string).map_err(|err| Error::custom(err.to_string())))
}