// - Parent
use super::*;

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
    let set_index = binary_search_for_map_in_set(offset_maps, offset)?;
    let map = offset_maps.iter().nth(set_index)?;
    let (_, (segment_no, offset)) = map.range(..=offset).next_back()?;
    Some((*segment_no, *offset))
}

fn binary_search_for_map_in_set(set: &BTreeSet<BTreeMap<u64, (u64, u64)>>, offset: u64) -> Option<usize> {
    // The zombie counter is used to prevent infinite loops (if the set is malformed, etc.)
    let mut zombie_counter = 0;
    let mut low = 0;
    let mut high = set.len() - 1;
    while low <= high {
        if zombie_counter > DEFAULT_BINARY_SEARCH_MAX_ITERATIONS {
            #[cfg(feature = "log")]
            debug!("Malformed VMI map. Exiting.");
            return None;
        }
        let mid = (low + high) / 2;
        let lowest_offset = set.iter().nth(mid)?.keys().next()?;
        let highest_offset = set.iter().nth(mid)?.keys().next_back()?;
        if lowest_offset <= &offset && highest_offset >= &offset {
            // returns the appropriate set index
            return Some(mid);
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
    None
}


#[cfg(feature = "serde")]
/// Serializes `buffer` to a lowercase hex string.
pub fn buffer_to_hex<T, S>(buffer: &T, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where T: AsRef<[u8]>,
        S: serde::Serializer
{
  serializer.serialize_str(&hex::encode(buffer))
}

#[cfg(feature = "serde")]
/// Deserializes a lowercase hex string to a `Vec<u8>`.
pub fn hex_to_buffer<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
  where D: serde::Deserializer<'de>
{
  use serde::de::Error;
  String::deserialize(deserializer)
    .and_then(|string| Vec::from_hex(string).map_err(|err| Error::custom(err.to_string())))
}

#[cfg(feature = "serde")]
/// Serializes `buffer` to a lowercase base64 string.
pub fn buffer_to_base64<T, S>(buffer: &T, serializer: S) -> std::result::Result<S::Ok, S::Error>
where 
    T: AsRef<[u8]>,
    S: serde::Serializer
{
    serializer.serialize_str(&base64engine.encode(buffer))
}

#[cfg(feature = "serde")]
/// Serializes `buffer` (Option) to a lowecase base64 Option<String>.
pub fn option_buffer_to_base64<S>(buffer: &Option<Vec<u8>>, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer
{
    match buffer {
        Some(buffer) => buffer_to_base64(&buffer, serializer),
        None => serializer.serialize_none(),
    }
}

#[cfg(feature = "serde")]
/// Deserializes a lowercase base64 string to a `Vec<u8>`.
pub fn base64_to_buffer<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
  where D: serde::Deserializer<'de>
{
    use serde::de::Error;
    String::deserialize(deserializer).and_then(|string| base64engine.decode(string).map_err(|err| Error::custom(err.to_string())))
}


/// Returns the segment number of a given chunk number.
pub fn get_segment_of_chunk_no(chunk_no: u64, mainfooter_chunkmap: &BTreeMap<u64, u64>) -> Option<u64> {
    // If the chunk_no is exactly matched, return the corresponding value.
    if let Some(&value) = mainfooter_chunkmap.get(&chunk_no) {
        return Some(value);
    }

    // If the chunk_no is higher than the highest key, return None.
    if let Some((&highest_chunk_no, _)) = mainfooter_chunkmap.iter().next_back() {
        if chunk_no > highest_chunk_no {
            return None;
        }
    }

    // Find the next higher key and return its value.
    if let Some((_, &segment_no)) = mainfooter_chunkmap.iter().find(|(&key, _)| key > chunk_no) {
        return Some(segment_no);
    }

    // If no next higher key is found, it means the chunk_no is higher than all keys,
    // so we should return None.
    None
}
