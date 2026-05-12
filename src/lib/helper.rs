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

/// Returns the greatest key-value pair in the sorted slice whose key is less
/// than or equal to `key`.
#[inline]
pub fn floor_vec_entry<T>(items: &[(u64, T)], key: u64) -> Option<&(u64, T)> {
    match items.binary_search_by_key(&key, |(k, _)| *k) {
        Ok(i) => items.get(i),
        Err(0) => None,
        Err(i) => items.get(i - 1),
    }
}

/// Returns the value belonging to the greatest key in the sorted slice that is
/// less than or equal to `key`.
#[inline]
pub fn floor_vec_value<T>(items: &[(u64, T)], key: u64) -> Option<&T> {
    floor_vec_entry(items, key).map(|(_, v)| v)
}

/// Returns the greatest key-value pair whose key is less than or equal to
/// `key`.
#[inline]
pub fn floor_btree_entry<T>(map: &BTreeMap<u64, T>, key: u64) -> Option<(&u64, &T)> {
    map.range(..=key).next_back()
}

/// Returns the value belonging to the greatest key that is less than or equal
/// to `key`.
#[inline]
pub fn floor_btree_value<T>(map: &BTreeMap<u64, T>, key: u64) -> Option<&T> {
    floor_btree_entry(map, key).map(|(_, v)| v)
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
pub(crate) fn get_segment_of_chunk_no(chunk_no: u64, mainfooter_chunkmap: &BTreeMap<u64, u64>) -> Option<u64> {
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

pub(crate) fn result_combine<T, V>(t: (Result<T>, V)) -> Result<(T, V)> {
    let (r, x) = t;
    r.map(|v| (v, x))
}

/// merges the major and minor rdev to a single rdev.
#[cfg(feature = "los_tar")]
pub(crate) fn makedev(major: u32, minor: u32) -> u64 {
    let major = major as u64;
    let minor = minor as u64;
    
    ((major & 0xfff) << 8)
        | (minor & 0xff)
        | ((minor & !0xff) << 12)
}

#[cfg(feature = "los_tar")]
pub(crate) fn parse_unix_timestamp_nanos(s: &str) -> Option<u64> {
    let bytes = s.as_bytes();

    let mut secs: u64 = 0;
    let mut nanos: u64 = 0;
    let mut seen_dot = false;
    let mut frac_digits = 0usize;

    for &b in bytes {
        if b == b'.' {
            if seen_dot {
                return None; // second dot
            }
            seen_dot = true;
            continue;
        }

        if !b.is_ascii_digit() {
            return None;
        }

        let digit = (b - b'0') as u64;

        if !seen_dot {
            secs = secs.checked_mul(10)?.checked_add(digit)?;
        } else if frac_digits < 9 {
                nanos = nanos.checked_mul(10)?.checked_add(digit)?;
                frac_digits += 1;
        }
        // extra digits silently ignored
    }

    // scale to nanoseconds
    if seen_dot {
        for _ in frac_digits..9 {
            nanos = nanos.checked_mul(10)?;
        }
    }

    secs.checked_mul(1_000_000_000)?.checked_add(nanos)
}
