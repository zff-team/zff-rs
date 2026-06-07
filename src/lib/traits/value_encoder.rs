// - Parent
use super::encode_key;

/// encoder methods for values (and primitive types). This is an extension trait.
///
/// # Example
/// ```no_run
/// use zff::ValueEncoder;
///
/// // Implementing ValueEncoder for a custom type
/// struct MyType(u32);
///
/// impl ValueEncoder for MyType {
///     fn encode_directly(&self) -> Vec<u8> {
///         self.0.to_le_bytes().to_vec()
///     }
///     fn identifier(&self) -> u8 { 0xFF }
///     fn encoded_size(&self) -> usize { 4 }
/// }
///
/// let my_value = MyType(42);
/// let encoded = my_value.encode_directly();
/// assert_eq!(encoded, vec![42, 0, 0, 0]);
/// ```
pub trait ValueEncoder {
    /// encodes the value directly (= without key).
    ///
    /// # Example
    /// ```no_run
    /// use zff::ValueEncoder;
    ///
    /// let value: u32 = 42;
    /// let encoded = value.encode_directly();
    /// ```
    fn encode_directly(&self) -> Vec<u8>;
    /// encodes a key to the value.
    ///
    /// # Example
    /// ```no_run
    /// use zff::ValueEncoder;
    ///
    /// let value: u32 = 42;
    /// let encoded = value.encode_for_key("my_key");
    /// // The encoded bytes include both the key and the value
    /// ```
    fn encode_for_key(&self, key: &str) -> Vec<u8> {
        let mut vec = Vec::new();
        let mut encoded_key = encode_key(key);
        vec.append(&mut encoded_key);
        vec.append(&mut self.encode_directly());
        vec
    }

    /// encodes with the appropriate type identifier.
    ///
    /// # Example
    /// ```no_run
    /// use zff::ValueEncoder;
    ///
    /// let value: u32 = 42;
    /// let encoded = value.encode_with_identifier();
    /// // First byte is the type identifier, rest is the encoded value
    /// ```
    fn encode_with_identifier(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.push(self.identifier());
        vec.append(&mut self.encode_directly());
        vec
    }

    /// returns the identifier of the appropriate type.
    ///
    /// # Example
    /// ```no_run
    /// use zff::ValueEncoder;
    ///
    /// let value: u32 = 42;
    /// let id = value.identifier();
    /// // id is the type identifier byte
    /// ```
    fn identifier(&self) -> u8;

    /// Returns the size of an encoded element.
    ///
    /// # Example
    /// ```no_run
    /// use zff::ValueEncoder;
    ///
    /// let value: u32 = 42;
    /// let size = value.encoded_size();
    /// assert_eq!(size, 4);
    /// ```
    fn encoded_size(&self) -> usize;
}
