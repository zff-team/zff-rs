//TODO: Convert the Encryption struct to an Encryption Trait which could be implemented by the different types.
// - STD
use std::borrow::Borrow;
use std::fmt;
// - internal
use crate::{
	Result, ZffError, ZffErrorKind, SCRYPT_DERIVED_KEY_LENGTH_AES_128, SCRYPT_DERIVED_KEY_LENGTH_AES_256
};

// - external
use pkcs5::{
	EncryptionScheme,
	pbes2::Parameters as PBES2Parameters,
	scrypt::Params as ScryptParams
};
use argon2::{Config, Variant, Version};
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes_gcm::{
	Aes256Gcm, Aes128Gcm, Nonce as AesGcmNonce, KeyInit,
	aead::Aead,
};
use chacha20poly1305::ChaCha20Poly1305;
use byteorder::{LittleEndian, WriteBytesExt};
use rand::{rngs::OsRng, RngCore};
use typenum::consts::U12;

#[cfg(feature = "serde")]
use serde::{
	Deserialize,
	Serialize,
};


// - type definitions
type Nonce = AesGcmNonce<U12>; //use the (by NIST) recommended nonce size of 96-bit.

/// Defines all encryption algorithms (for use in data and header encryption), which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum EncryptionAlgorithm {
	/// AES (128-Bit) in Galois/Counter Mode operation.  
	/// Encoded with value 0.
	AES128GCM = 0,
	/// AES (256-Bit) in Galois/Counter Mode operation.  
	/// Encoded with value 1.
	AES256GCM = 1,
	/// Chacha20 stream cipher with Poly1305 universal hash function.
	CHACHA20POLY1305 = 2,
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    	let value = match self {
    		EncryptionAlgorithm::AES128GCM => "AES128GCM",
    		EncryptionAlgorithm::AES256GCM => "AES256GCM",
    		EncryptionAlgorithm::CHACHA20POLY1305 => "CHACHA20POLY1305",
    	};
        write!(f, "{value}")
    }
}

/// Defines all KDF schemes, which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum KDFScheme {
	/// KDF scheme PBKDF2-SHA256, with encoding value 0.
	PBKDF2SHA256 = 0,
	/// KDF scheme scrypt, with encoding value 1.
	Scrypt = 1,
	/// KDF scheme Argon2(id), with encoding value 2.
	Argon2id = 2,
}

impl fmt::Display for KDFScheme {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    	let value = match self {
    		KDFScheme::PBKDF2SHA256 => "PBKDF2-SHA256",
    		KDFScheme::Scrypt => "Scrypt",
    		KDFScheme::Argon2id => "Argon2id",
    	};
        write!(f, "{value}")
    }
}

/// Defines all encryption algorithms (for use in PBE only!), which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum PBEScheme {
	/// AES128-CBC encryption scheme used in pbe with the encoding value 0.
	AES128CBC = 0,
	/// AES128-CBC encryption scheme used in pbe with the encoding value 1.
	AES256CBC = 1,
}

impl fmt::Display for PBEScheme {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    	let value = match self {
    		PBEScheme::AES128CBC => "AES128CBC",
    		PBEScheme::AES256CBC => "AES256CBC",
    	};
        write!(f, "{value}")
    }
}

/// Defines all encryption algorithms (for use in PBE only!), which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq)]
enum MessageType {
	ChunkData,
	FileHeader,
	FileFooter,
	ObjectHeader,
	ObjectFooter,
	VirtualMappingInformation,
	VirtualObjectMap,
	ChunkXxHashMap,
	ChunkDeduplicationMap,
	ChunkFlagsMap,
	ChunkOffsetMap,
	ChunkSameBytesMap,
	ChunkSizeMap,
}

/// Structure contains serveral methods to handle encryption
pub struct Encryption;

impl Encryption {
	/// Encrypts the given plaintext with the given values with PBKDF2-SHA256-AES128CBC, defined in PKCS#5.
	/// Returns the ciphertext as ```Vec<u8>```.
	/// # Error
	/// if the encryption fails, or the given parameters are false.
	pub fn encrypt_pbkdf2sha256_aes128cbc(
		iterations: u32,
		salt: &[u8; 32],
		aes_iv: &[u8; 16],
		password: impl AsRef<[u8]>,
		plaintext: &[u8]) -> Result<Vec<u8>> {
		let params = PBES2Parameters::pbkdf2_sha256_aes128cbc(iterations, salt, aes_iv)?;
		let encryption_scheme = EncryptionScheme::Pbes2(params);
		Ok(encryption_scheme.encrypt(password, plaintext)?)
	}

	/// Encrypts the given plaintext with the given values with PBKDF2-SHA256-AES256CBC, defined in PKCS#5.
	/// Returns the ciphertext as ```Vec<u8>```.
	/// # Error
	/// if the encryption fails, or the given parameters are false.
	pub fn encrypt_pbkdf2sha256_aes256cbc(
		iterations: u32,
		salt: &[u8; 32],
		aes_iv: &[u8; 16],
		password: impl AsRef<[u8]>,
		plaintext: &[u8]) -> Result<Vec<u8>> {
		let params = PBES2Parameters::pbkdf2_sha256_aes256cbc(iterations, salt, aes_iv)?;
		let encryption_scheme = EncryptionScheme::Pbes2(params);
		let cipher = encryption_scheme.encrypt(password, plaintext)?;
		Ok(cipher)
	}

	/// Decrypts the given ciphertext from the given values with PBKDF2-SHA256-AES128CBC, defined in PKCS#5.
	/// Returns the plaintext as ```Vec<u8>```.
	/// # Error
	/// if the decryption fails, or the given parameters are false.
	pub fn decrypt_pbkdf2sha256_aes128cbc(
		iterations: u32,
		salt: &[u8; 32],
		aes_iv: &[u8; 16],
		password: impl AsRef<[u8]>,
		ciphertext: &[u8]) -> Result<Vec<u8>> {
		let params = PBES2Parameters::pbkdf2_sha256_aes128cbc(iterations, salt, aes_iv)?;
		let encryption_scheme = EncryptionScheme::Pbes2(params);
		Ok(encryption_scheme.decrypt(password, ciphertext)?)
	}

	/// Decrypts the given ciphertext from the given values with PBKDF2-SHA256-AES256CBC, defined in PKCS#5.
	/// Returns the plaintext as ```Vec<u8>```.
	/// # Error
	/// if the decryption fails, or the given parameters are false.
	pub fn decrypt_pbkdf2sha256_aes256cbc(
		iterations: u32,
		salt: &[u8; 32],
		aes_iv: &[u8; 16],
		password: impl AsRef<[u8]>,
		ciphertext: &[u8]) -> Result<Vec<u8>> {
		let params = PBES2Parameters::pbkdf2_sha256_aes256cbc(iterations, salt, aes_iv)?;
		let encryption_scheme = EncryptionScheme::Pbes2(params);
		Ok(encryption_scheme.decrypt(password, ciphertext)?)
	}

	/// Encrypts the given plaintext with the given values with Scrypt-AES128CBC.
	/// Returns the ciphertext as ```Vec<u8>```.
	/// # Error
	/// if the encryption fails, or the given parameters are false.
	pub fn encrypt_scrypt_aes128cbc(
		logn: u8,
		r: u32,
		p: u32,
		salt: &[u8; 32],
		aes_iv: &[u8; 16],
		password: impl AsRef<[u8]>,
		plaintext: &[u8]) -> Result<Vec<u8>> {
		let params = PBES2Parameters::scrypt_aes128cbc(ScryptParams::new(logn, r, p, SCRYPT_DERIVED_KEY_LENGTH_AES_128)?, salt, aes_iv)?;
		let encryption_scheme = EncryptionScheme::Pbes2(params);
		Ok(encryption_scheme.encrypt(password, plaintext)?)
	}

	/// Encrypts the given plaintext with the given values with Scrypt-AES256CBC.
	/// Returns the ciphertext as ```Vec<u8>```.
	/// # Error
	/// if the encryption fails, or the given parameters are false.
	pub fn encrypt_scrypt_aes256cbc(
		logn: u8,
		r: u32,
		p: u32,
		salt: &[u8; 32],
		aes_iv: &[u8; 16],
		password: impl AsRef<[u8]>,
		plaintext: &[u8]) -> Result<Vec<u8>> {
		let params = PBES2Parameters::scrypt_aes256cbc(ScryptParams::new(logn, r, p, SCRYPT_DERIVED_KEY_LENGTH_AES_256)?, salt, aes_iv)?;
		let encryption_scheme = EncryptionScheme::Pbes2(params);
		Ok(encryption_scheme.encrypt(password, plaintext)?)
	}

	/// Decrypts the given ciphertext with the given values with Scrypt-AES128CBC.
	/// Returns the plaintext as ```Vec<u8>```.
	/// # Error
	/// if the encryption fails, or the given parameters are false.
	pub fn decrypt_scrypt_aes128cbc(
		logn: u8,
		r: u32,
		p: u32,
		salt: &[u8; 32],
		aes_iv: &[u8; 16],
		password: impl AsRef<[u8]>,
		plaintext: &[u8]) -> Result<Vec<u8>> {
		let params = PBES2Parameters::scrypt_aes128cbc(ScryptParams::new(logn, r, p, SCRYPT_DERIVED_KEY_LENGTH_AES_128)?, salt, aes_iv)?;
		let encryption_scheme = EncryptionScheme::Pbes2(params);
		Ok(encryption_scheme.decrypt(password, plaintext)?)
	}

	/// Decrypts the given ciphertext with the given values with Scrypt-AES256CBC.
	/// Returns the plaintext as ```Vec<u8>```.
	/// # Error
	/// if the encryption fails, or the given parameters are false.
	pub fn decrypt_scrypt_aes256cbc(
		logn: u8,
		r: u32,
		p: u32,
		salt: &[u8; 32],
		aes_iv: &[u8; 16],
		password: impl AsRef<[u8]>,
		plaintext: &[u8]) -> Result<Vec<u8>> {
		let params = PBES2Parameters::scrypt_aes256cbc(ScryptParams::new(logn, r, p, SCRYPT_DERIVED_KEY_LENGTH_AES_256)?, salt, aes_iv)?;
		let encryption_scheme = EncryptionScheme::Pbes2(params);
		Ok(encryption_scheme.decrypt(password, plaintext)?)
	}

	/// Encrypts the given plaintext with the given values with Argon2id-AES128CBC.
	/// Returns the ciphertext as ```Vec<u8>```.
	/// # Error
	/// if the encryption fails, or the given parameters are false.
	pub fn encrypt_argon2_aes128cbc(
		mem_cost: u32,
		lanes: u32,
		iterations: u32,
		salt: &[u8; 32],
		aes_iv: &[u8; 16],
		password: impl AsRef<[u8]>,
		plaintext: &[u8]) -> Result<Vec<u8>> {
		let scheme = PBEScheme::AES128CBC;
		let password = &String::from_utf8(password.as_ref().to_vec())?;
		encrypt_argon2_aes(password, salt, mem_cost, lanes, iterations, scheme, aes_iv, plaintext)
	}

	/// Encrypts the given plaintext with the given values with Argon2id-AES256CBC.
	/// Returns the ciphertext as ```Vec<u8>```.
	/// # Error
	/// if the encryption fails, or the given parameters are false.
	pub fn encrypt_argon2_aes256cbc(
		mem_cost: u32,
		lanes: u32,
		iterations: u32,
		salt: &[u8; 32],
		aes_iv: &[u8; 16],
		password: impl AsRef<[u8]>,
		plaintext: &[u8]) -> Result<Vec<u8>> {
		let scheme = PBEScheme::AES256CBC;
		let password = &String::from_utf8(password.as_ref().to_vec())?;
		encrypt_argon2_aes(password, salt, mem_cost, lanes, iterations, scheme, aes_iv, plaintext)
	}

	/// Decrypts the given ciphertext with the given values with Argon2id-AES128CBC.
	/// Returns the ciphertext as ```Vec<u8>```.
	/// # Error
	/// if the decryption fails, or the given parameters are false.
	pub fn decrypt_argon2_aes128cbc(
		mem_cost: u32,
		lanes: u32,
		iterations: u32,
		salt: &[u8; 32],
		aes_iv: &[u8; 16],
		password: impl AsRef<[u8]>,
		plaintext: &[u8]) -> Result<Vec<u8>> {
		let scheme = PBEScheme::AES128CBC;
		let password = &String::from_utf8(password.as_ref().to_vec())?;
		decrypt_argon2_aes(password, salt, mem_cost, lanes, iterations, scheme, aes_iv, plaintext)
	}

	/// Decrypts the given ciphertext with the given values with Argon2id-AES128CBC.
	/// Returns the ciphertext as ```Vec<u8>```.
	/// # Error
	/// if the decryption fails, or the given parameters are false.
	pub fn decrypt_argon2_aes256cbc(
		mem_cost: u32,
		lanes: u32,
		iterations: u32,
		salt: &[u8; 32],
		aes_iv: &[u8; 16],
		password: impl AsRef<[u8]>,
		plaintext: &[u8]) -> Result<Vec<u8>> {
		let scheme = PBEScheme::AES256CBC;
		let password = &String::from_utf8(password.as_ref().to_vec())?;
		decrypt_argon2_aes(password, salt, mem_cost, lanes, iterations, scheme, aes_iv, plaintext)
	}

	/// Method to encrypt a chunk content with a key and and the given chunk number. This method should primary used to encrypt
	/// the given chunk data (if selected, then **after the compression**).
	/// Returns a the cipthertext as ```Vec<u8>```.
	/// # Example
	/// ```
	/// use zff::*;
	/// use hex::ToHex;
	///
	/// fn main() -> Result<()> {
	///        let key = "01234567890123456789012345678912"; // 32Byte/256Bit Key
	///        let chunk_no = 1; // 12Byte/96Bit Key
	///        let message = "My message";
	/// 
	///        let ciphertext = Encryption::encrypt_chunk_content(key, message, chunk_no, EncryptionAlgorithm::AES256GCM)?;
	/// 
	///        assert_eq!(ciphertext.encode_hex::<String>(), "3f1879c7e3373af75b5b4e857cd88ab7c6db604cef2e60c5df42".to_string());
	///        Ok(())
	/// }
	/// ```
	/// # Error
	/// This method will fail, if the encryption fails.
	pub fn encrypt_chunk_content<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, chunk_no, algorithm, MessageType::ChunkData)
	}

	/// Method to encrypt a [crate::header::VirtualMappingInformation] with a key and and the given offset. This method should primary used to encrypt
	/// the given [crate::header::VirtualMappingInformation].
	/// Returns a the cipthertext as ```Vec<u8>```.
	pub fn encrypt_virtual_mapping_information<K, M, A>(key: K, message: M, offset: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, offset, algorithm, MessageType::VirtualMappingInformation)
	}

	/// Method to encrypt a [crate::header::VirtualObjectMap] with a key and and the given depth. This method should primary used to encrypt
	/// the given [crate::header::VirtualObjectMap].
	/// Returns a the cipthertext as ```Vec<u8>```.
	pub fn encrypt_virtual_object_map<K, M, A>(key: K, message: M, object_number: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, object_number, algorithm, MessageType::VirtualObjectMap)
	}


	/// Method to encrypt a [crate::header::FileHeader] with a key and and the given chunk number. This method should primary used to encrypt
	/// the given [crate::header::FileHeader].
	/// Returns a the cipthertext as ```Vec<u8>```.
	pub fn encrypt_file_header<K, M, A>(key: K, message: M, file_number: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, file_number, algorithm, MessageType::FileHeader)
	}

	/// Method to encrypt a [crate::footer::FileFooter] with a key and and the given chunk number. This method should primary used to encrypt
	/// the given [crate::footer::FileFooter].
	/// Returns a the cipthertext as ```Vec<u8>```.
	pub fn encrypt_file_footer<K, M, A>(key: K, message: M, file_number: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, file_number, algorithm, MessageType::FileFooter)
	}

	/// Method to encrypt a [crate::header::ObjectHeader] with a key and and the given chunk number. This method should primary used to encrypt
	/// the given [crate::header::ObjectHeader].
	/// Returns a the cipthertext as ```Vec<u8>```.
	pub fn encrypt_object_header<K, M, A>(key: K, message: M, object_number: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, object_number, algorithm, MessageType::ObjectHeader)
	}

	/// Method to encrypt a [crate::footer::ObjectFooter] with a key and and the given chunk number. This method should primary used to encrypt
	/// the given [crate::footer::ObjectFooter].
	/// Returns a the cipthertext as ```Vec<u8>```.
	pub fn encrypt_object_footer<K, M, A>(key: K, message: M, object_number: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, object_number, algorithm, MessageType::ObjectFooter)
	}

	/// Method to encrypt a [crate::header::ChunkXxHashMap] with a key and and the given chunk number. This method should primary used to encrypt
	/// the given [crate::header::ChunkXxHashMap].
	/// Returns a the cipthertext as ```Vec<u8>```.
	pub fn encrypt_chunk_xxhash_map<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, chunk_no, algorithm, MessageType::ChunkXxHashMap)
	}

	/// Method to encrypt a [crate::header::ChunkDeduplicationMap] with a key and and the given chunk number. This method should primary used to encrypt
	/// the given [crate::header::ChunkDeduplicationMap].
	/// Returns a the cipthertext as ```Vec<u8>```.
	pub fn encrypt_chunk_deduplication_map<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, chunk_no, algorithm, MessageType::ChunkDeduplicationMap)
	}

	/// Method to encrypt a [crate::header::ChunkFlagMap] with a key and and the given chunk number. This method should primary used to encrypt
	/// the given [crate::header::ChunkFlagMap].
	/// Returns a the cipthertext as ```Vec<u8>```.
	pub fn encrypt_chunk_flags_map<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, chunk_no, algorithm, MessageType::ChunkFlagsMap)
	}

	/// Method to encrypt a [crate::header::ChunkOffsetMap] with a key and and the given chunk number. This method should primary used to encrypt
	/// the given [crate::header::ChunkOffsetMap].
	/// Returns a the cipthertext as ```Vec<u8>```.
	pub fn encrypt_chunk_offset_map<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, chunk_no, algorithm, MessageType::ChunkOffsetMap)
	}

	/// Method to encrypt a [crate::header::ChunkSamebytesMap] with a key and and the given chunk number. This method should primary used to encrypt
	/// the given [crate::header::ChunkSamebytesMap].
	/// Returns a the cipthertext as ```Vec<u8>```.
	pub fn encrypt_chunk_samebytes_map<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, chunk_no, algorithm, MessageType::ChunkSameBytesMap)
	}

	/// Method to encrypt a [crate::header::ChunkSizeMap] with a key and and the given chunk number. This method should primary used to encrypt
	/// the given [crate::header::ChunkSizeMap].
	/// Returns a the cipthertext as ```Vec<u8>```.
	pub fn encrypt_chunk_size_map<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, chunk_no, algorithm, MessageType::ChunkSizeMap)
	}

	/// Method to decrypt a chunk content with a key and and the given chunk number. This method should primary used to decrypt
	/// the given chunk data (if selected, then **before the decompression**).
	/// Returns a the plaintext as ```Vec<u8>``` of the given ciphertext.
	/// # Error
	/// This method will fail, if the decryption fails.
	pub fn decrypt_chunk_content<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::decrypt_message(key, message, chunk_no, algorithm, MessageType::ChunkData)
	}

	/// Method to decrypt a [crate::header::VirtualMappingInformation] with a key and and the given offset. This method should primary used to decrypt
	/// the given [crate::header::VirtualMappingInformation].
	/// Returns a the plaintext as ```Vec<u8>``` of the given ciphertext.
	/// # Error
	/// This method will fail, if the decryption fails.
	pub fn decrypt_virtual_mapping_information<K, M, A>(key: K, message: M, offset: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::decrypt_message(key, message, offset, algorithm, MessageType::VirtualMappingInformation)
	}

	/// Method to decrypt a [VirtualLayer](crate::header::VirtualObjectMap) with a key and and the given depth. This method should primary used to decrypt
	/// the given [VirtualLayer](crate::header::VirtualObjectMap).
	/// Returns a the plaintext as ```Vec<u8>``` of the given ciphertext.
	/// # Error
	/// This method will fail, if the decryption fails.
	pub fn decrypt_virtual_object_map<K, M, A>(key: K, message: M, object_number: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::decrypt_message(key, message, object_number, algorithm, MessageType::VirtualObjectMap)
	}

	/// Method to decrypt a [crate::header::FileHeader] with a key and and the given chunk number. This method should primary used to decrypt
	/// a [crate::header::FileHeader].
	/// Returns a the plaintext as ```Vec<u8>``` of the given ciphertext.
	/// # Error
	/// This method will fail, if the decryption fails.
	pub fn decrypt_file_header<K, M, A>(key: K, message: M, file_number: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::decrypt_message(key, message, file_number, algorithm, MessageType::FileHeader)
	}

	/// Method to decrypt a [crate::footer::FileFooter] with a key and and the given chunk number. This method should primary used to decrypt
	/// a [crate::footer::FileFooter].
	/// Returns a the plaintext as ```Vec<u8>``` of the given ciphertext.
	/// # Error
	/// This method will fail, if the decryption fails.
	pub fn decrypt_file_footer<K, M, A>(key: K, message: M, file_number: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::decrypt_message(key, message, file_number, algorithm, MessageType::FileFooter)
	}

	/// Method to decrypt a [crate::header::ObjectHeader] with a key and and the given chunk number. This method should primary used to decrypt
	/// a [crate::header::ObjectHeader].
	/// Returns a the plaintext as ```Vec<u8>``` of the given ciphertext.
	/// # Error
	/// This method will fail, if the decryption fails.
	pub fn decrypt_object_header<K, M, A>(key: K, message: M, object_number: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::decrypt_message(key, message, object_number, algorithm, MessageType::ObjectHeader)
	}

	/// Method to decrypt a [crate::footer::ObjectFooter] with a key and and the given chunk number. This method should primary used to decrypt
	/// a [crate::footer::ObjectFooter].
	/// Returns a the plaintext as ```Vec<u8>``` of the given ciphertext.
	/// # Error
	/// This method will fail, if the decryption fails.
	pub fn decrypt_object_footer<K, M, A>(key: K, message: M, object_number: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::decrypt_message(key, message, object_number, algorithm, MessageType::ObjectFooter)
	}

	/// Method to decrypt a [crate::header::ChunkXxHashMap] with a key and and the given chunk number. This method should primary used to decrypt
	/// a [crate::header::ChunkXxHashMap].
	/// Returns a the plaintext as ```Vec<u8>``` of the given ciphertext.
	/// # Error
	/// This method will fail, if the decryption fails.
	pub fn decrypt_chunk_xxhash_map<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::decrypt_message(key, message, chunk_no, algorithm, MessageType::ChunkXxHashMap)
	}

	/// Method to decrypt a [crate::header::ChunkDeduplicationMap] with a key and and the given chunk number. This method should primary used to decrypt
	/// a [crate::header::ChunkDeduplicationMap].
	/// Returns a the plaintext as ```Vec<u8>``` of the given ciphertext.
	/// # Error
	/// This method will fail, if the decryption fails.
	pub fn decrypt_chunk_deduplication_map<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::decrypt_message(key, message, chunk_no, algorithm, MessageType::ChunkDeduplicationMap)
	}

	/// Method to decrypt a [crate::header::ChunkFlagsMap] with a key and and the given chunk number. This method should primary used to decrypt
	/// a [crate::header::ChunkFlagsMap].
	/// Returns a the plaintext as ```Vec<u8>``` of the given ciphertext.
	/// # Error
	/// This method will fail, if the decryption fails.
	pub fn decrypt_chunk_flags_map<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::decrypt_message(key, message, chunk_no, algorithm, MessageType::ChunkFlagsMap)
	}

	/// Method to decrypt a [crate::header::ChunkOffsetMap] with a key and and the given chunk number. This method should primary used to decrypt
	/// a [crate::header::ChunkOffsetMap].
	/// Returns a the plaintext as ```Vec<u8>``` of the given ciphertext.
	/// # Error
	/// This method will fail, if the decryption fails.
	pub fn decrypt_chunk_offset_map<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::decrypt_message(key, message, chunk_no, algorithm, MessageType::ChunkOffsetMap)
	}

	/// Method to decrypt a [crate::header::ChunkSamebytesMap] with a key and and the given chunk number. This method should primary used to decrypt
	/// a [crate::header::ChunkSamebytesMap].
	/// Returns a the plaintext as ```Vec<u8>``` of the given ciphertext.
	/// # Error
	/// This method will fail, if the decryption fails.
	pub fn decrypt_chunk_samebytes_map<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::decrypt_message(key, message, chunk_no, algorithm, MessageType::ChunkSameBytesMap)
	}

	/// Method to decrypt a [crate::header::ChunkSizeMap] with a key and and the given chunk number. This method should primary used to decrypt
	/// a [crate::header::ChunkSizeMap].
	/// Returns a the plaintext as ```Vec<u8>``` of the given ciphertext.
	/// # Error
	/// This method will fail, if the decryption fails.
	pub fn decrypt_chunk_size_map<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::decrypt_message(key, message, chunk_no, algorithm, MessageType::ChunkSizeMap)
	}

	fn encrypt_message<K, M, A, T>(key: K, message: M, nonce_value: u64, algorithm: A, message_type: T) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
		T: Borrow<MessageType>,
	{
		let nonce = Self::gen_crypto_nonce(nonce_value, message_type)?;

		match algorithm.borrow() {
			EncryptionAlgorithm::AES256GCM => {
				let cipher = Aes256Gcm::new_from_slice(key.as_ref())?;
				Ok(cipher.encrypt(&nonce, message.as_ref())?)
			},
			EncryptionAlgorithm::AES128GCM => {
				let cipher = Aes128Gcm::new_from_slice(key.as_ref())?;
				Ok(cipher.encrypt(&nonce, message.as_ref())?)
			},
			EncryptionAlgorithm::CHACHA20POLY1305 => {
				let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())?;
				Ok(cipher.encrypt(&nonce, message.as_ref())?)
			}
		}
	}

	fn decrypt_message<K, M, A, T>(key: K, message: M, nonce_value: u64, algorithm: A, message_type: T) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
		T: Borrow<MessageType>
	{
		let nonce = Self::gen_crypto_nonce(nonce_value, message_type)?;

		match algorithm.borrow() {
			EncryptionAlgorithm::AES256GCM => {
				let cipher = Aes256Gcm::new_from_slice(key.as_ref())?;
				Ok(cipher.decrypt(&nonce, message.as_ref())?)
			},
			EncryptionAlgorithm::AES128GCM => {
				let cipher = Aes128Gcm::new_from_slice(key.as_ref())?;
				Ok(cipher.decrypt(&nonce, message.as_ref())?)
			},
			EncryptionAlgorithm::CHACHA20POLY1305 => {
				let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())?;
				Ok(cipher.decrypt(&nonce, message.as_ref())?)
			}
		}
	}

	/// Generates a new random key, with the given key size.
	/// # Example
	/// ```no_run
	/// use zff::*;
	/// 
	/// let keysize = 256; //(e.g. for use as 256-Bit-AES-Key).
	/// let my_new_random_super_secret_key = Encryption::gen_random_key(keysize);
	/// //...
	/// ```
	pub fn gen_random_key(length: usize) -> Vec<u8> {
		let mut key = vec!(0u8; length/8);
		let mut rng = OsRng;
		rng.fill_bytes(&mut key);
		key
	}

	/// Generates a new random IV/Nonce as ```[u8; 16]``` for use in PBE header.
	pub fn gen_random_iv() -> [u8; 16] {
		let mut iv = [0; 16];
		let mut rng = OsRng;
		rng.fill_bytes(&mut iv);
		iv
	}

	/// Generates a new random salt as ```[u8; 32]``` for use in PBE header.
	pub fn gen_random_salt() -> [u8; 32] {
		let mut salt = [0; 32];
		let mut rng = OsRng;
		rng.fill_bytes(&mut salt);
		salt
	}

	/// Generates a new random IV/Nonce as ```[u8; 12]``` for use in encryption header.
	pub fn gen_random_header_nonce() -> [u8; 12] {
		let mut nonce = [0; 12];
		let mut rng = OsRng;
		rng.fill_bytes(&mut nonce);
		nonce
	}

	/// Method to generate a 96-bit nonce for the appropriate message type (using the given value).
	fn gen_crypto_nonce<T: Borrow<MessageType>>(nonce_value: u64, message_type: T) -> Result<Nonce> {
		let mut buffer = vec![];
		buffer.write_u64::<LittleEndian>(nonce_value)?;
		buffer.append(&mut vec!(0u8; 4));
		let buffer_len = buffer.len();
		match message_type.borrow() {
			MessageType::ChunkData => (), // fills the missing bits with zeros
			MessageType::FileHeader => buffer[buffer_len - 1] |= 0b00000100,
			MessageType::FileFooter => buffer[buffer_len - 1] |= 0b00001000,
			MessageType::ObjectHeader => buffer[buffer_len - 1] |= 0b00010000,
			MessageType::ObjectFooter => buffer[buffer_len - 1] |= 0b00100000,
			MessageType::VirtualMappingInformation => buffer[buffer_len - 1] |= 0b00000010,
			MessageType::VirtualObjectMap => buffer[buffer_len - 1] |= 0b01000000,
			MessageType::ChunkXxHashMap => buffer[buffer_len - 1] |= 0b00001111,
			MessageType::ChunkDeduplicationMap => buffer[buffer_len - 1] |= 0b00111111,
			MessageType::ChunkFlagsMap => buffer[buffer_len - 1] |= 0b00000111,
			MessageType::ChunkOffsetMap => buffer[buffer_len - 1] |= 0b00000001,
			MessageType::ChunkSameBytesMap => buffer[buffer_len - 1] |= 0b00011111,
			MessageType::ChunkSizeMap => buffer[buffer_len - 1] |= 0b00000011,

		}
		Ok(*Nonce::from_slice(&buffer))
	}
}

// hash_length is 16 for aes128cbc and 32 for aes256cbc
fn hash_password_argon2(password: &str, salt: &[u8; 32], mem_cost: u32, lanes: u32, iterations: u32, hash_length: u32) -> Result<Vec<u8>> {
    let config = Config {
	    variant: Variant::Argon2id,
	    version: Version::Version13,
	    mem_cost,
	    time_cost: iterations,
	    lanes,
	    secret: &[],
	    ad: &[],
	    hash_length
	};
    Ok(argon2::hash_raw(password.as_bytes(), salt, &config)?)
}

#[allow(clippy::too_many_arguments)]
fn encrypt_argon2_aes<P>(
	password: &str, 
	salt: &[u8; 32], 
	mem_cost: u32, 
	lanes: u32, 
	iterations: u32,
	scheme: PBEScheme,
	aes_iv: &[u8; 16],
	plaintext: P) -> Result<Vec<u8>>
where
	P: AsRef<[u8]>,
{
	type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
	type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

	let hash = match scheme {
		PBEScheme::AES128CBC => hash_password_argon2(password, salt, mem_cost, lanes, iterations, 16)?,
		PBEScheme::AES256CBC => hash_password_argon2(password, salt, mem_cost, lanes, iterations, 32)?,
	};

	match scheme {
		PBEScheme::AES128CBC => {
			let key = &hash[0..16];
			Ok(Aes128CbcEnc::new(key.into(), aes_iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_ref()))
		},
		PBEScheme::AES256CBC => {
			let key = &hash[0..32];
			Ok(Aes256CbcEnc::new(key.into(), aes_iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_ref()))
		},
	}
}

#[allow(clippy::too_many_arguments)]
fn decrypt_argon2_aes<C>(
	password: &str, 
	salt: &[u8; 32], 
	mem_cost: u32, 
	lanes: u32,
	iterations: u32,
	scheme: PBEScheme,
	aes_iv: &[u8; 16], 
	ciphertext: C) -> Result<Vec<u8>>
where
	C: AsRef<[u8]>,
{
	type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
	type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

	let hash = match scheme {
		PBEScheme::AES128CBC => hash_password_argon2(password, salt, mem_cost, lanes, iterations, 16)?,
		PBEScheme::AES256CBC => hash_password_argon2(password, salt, mem_cost, lanes, iterations, 32)?,
	};

	match scheme {
		PBEScheme::AES128CBC => {
			let key = &hash[0..16];
			Ok(Aes128CbcDec::new(key.into(), aes_iv.into()).decrypt_padded_vec_mut::<Pkcs7>(ciphertext.as_ref())?)
		},
		PBEScheme::AES256CBC => {
			let key = &hash[0..32];
			Ok(Aes256CbcDec::new(key.into(), aes_iv.into()).decrypt_padded_vec_mut::<Pkcs7>(ciphertext.as_ref())?)
		},
	}
}
