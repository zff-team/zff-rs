#[cfg(feature = "serde")]
pub(crate) fn string_to_str(s: String) -> &'static str {
  Box::leak(s.into_boxed_str())
}

#[cfg(feature = "serde")]
pub(crate) fn as_hex<S>(x: &u64, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    s.serialize_str(&format!("0x{:X}", x))
}