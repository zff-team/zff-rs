// - STD
use std::borrow::Borrow;

// - internal
use crate::{
	Result,
	ZffError,
	ZffErrorKind,
	SCRYPT_DERIVED_KEY_LENGTH_AES_128,
	SCRYPT_DERIVED_KEY_LENGTH_AES_256
};

// - external
use pkcs5::{
	EncryptionScheme,
	pbes2::Parameters as PBES2Parameters,
	scrypt::Params as ScryptParams
};
use aes_gcm::{
	Aes256Gcm, Aes128Gcm, Nonce as AesGcmNonce, KeyInit,
	aead::{Aead},
};
use chacha20poly1305::{
    ChaCha20Poly1305
};
use ed25519_dalek::SIGNATURE_LENGTH;
use byteorder::{LittleEndian, WriteBytesExt};
use rand::{rngs::OsRng, RngCore};
use typenum::consts::U12;

// - type definitions
type Nonce = AesGcmNonce<U12>; //use the (by NIST) recommended nonce size of 96-bit.

/// Defines all encryption algorithms (for use in data and header encryption), which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq)]
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

/// Defines all KDF schemes, which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq)]
pub enum KDFScheme {
	/// KDF scheme PBKDF2-SHA256, with encoding value 0.
	PBKDF2SHA256 = 0,
	/// KDF scheme scrypt, with encoding value 1.
	Scrypt = 1,
}

/// Defines all encryption algorithms (for use in PBE only!), which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq)]
pub enum PBEScheme {
	/// AES128-CBC encryption scheme used in pbe with the encoding value 0.
	AES128CBC = 0,
	/// AES128-CBC encryption scheme used in pbe with the encoding value 1.
	AES256CBC = 1,
}

/// Defines all encryption algorithms (for use in PBE only!), which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq)]
enum MessageType {
	ChunkData,
	ChunkHeaderCRC32,
	ChunkHeaderEd25519,
	FileHeader,
	FileFooter,
	ObjectHeader,
	ObjectFooter,
}

/// structure contains serveral methods to handle encryption
pub struct Encryption;

impl Encryption {
	/// encrypts the given plaintext with the given values with PBKDF2-SHA256-AES128CBC, defined in PKCS#5.
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

	// encrypts the given plaintext with the given values with PBKDF2-SHA256-AES256CBC, defined in PKCS#5.
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

	/// decrypts the given ciphertext from the given values with PBKDF2-SHA256-AES128CBC, defined in PKCS#5.
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

	/// decrypts the given ciphertext from the given values with PBKDF2-SHA256-AES256CBC, defined in PKCS#5.
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

	/// encrypts the given plaintext with the given values with Scrypt-AES128CBC.
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

	/// encrypts the given plaintext with the given values with Scrypt-AES256CBC.
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

	/// decrypts the given ciphertext with the given values with Scrypt-AES128CBC.
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

	/// decrypts the given ciphertext with the given values with Scrypt-AES256CBC.
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

	/// method to encrypt a chunk content with a key and and the given chunk number. This method should primary used to encrypt
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
	///        let ciphertext = Encryption::encrypt_message(key, message, chunk_no, EncryptionAlgorithm::AES256GCMSIV)?;
	/// 
	///        assert_eq!(ciphertext.encode_hex::<String>(), "32f1c2f8ff6594a07eda5a4eca6d198f4cda8935f171d2345888".to_string());
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

	pub fn encrypt_chunk_header_crc32<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, chunk_no, algorithm, MessageType::ChunkHeaderCRC32)
	}

	pub fn encrypt_chunk_header_ed25519_signature<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, chunk_no, algorithm, MessageType::ChunkHeaderEd25519)
	}

	pub fn encrypt_file_header<K, M, A>(key: K, message: M, file_number: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, file_number, algorithm, MessageType::FileHeader)
	}

	pub fn encrypt_file_footer<K, M, A>(key: K, message: M, file_number: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, file_number, algorithm, MessageType::FileFooter)
	}

	pub fn encrypt_object_header<K, M, A>(key: K, message: M, object_number: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, object_number, algorithm, MessageType::ObjectHeader)
	}

	pub fn encrypt_object_footer<K, M, A>(key: K, message: M, object_number: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::encrypt_message(key, message, object_number, algorithm, MessageType::ObjectFooter)
	}

	/// method to decrypt a chunk content with a key and and the given chunk number. This method should primary used to decrypt
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

	pub fn decrypt_chunk_header_crc32<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<u32>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		let bytes: [u8; 4] = match Encryption::decrypt_message(
			key, message, chunk_no, algorithm, MessageType::ChunkHeaderCRC32)?.try_into() {
			Ok(bytes) => bytes,
			Err(_) => return Err(ZffError::new(ZffErrorKind::Custom, "")), //TODO: better error handling
		};
		Ok(u32::from_le_bytes(bytes))
	}

	pub fn decrypt_chunk_header_ed25519_signature<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<[u8; SIGNATURE_LENGTH]>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		let bytes: [u8; SIGNATURE_LENGTH] = match Encryption::decrypt_message(
			key, message, chunk_no, algorithm, MessageType::ChunkHeaderEd25519)?.try_into() {
			Ok(bytes) => bytes,
			Err(_) => return Err(ZffError::new(ZffErrorKind::Custom, "")), //TODO: better error handling
		};
		Ok(bytes)
	}

	pub fn decrypt_file_header<K, M, A>(key: K, message: M, file_number: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::decrypt_message(key, message, file_number, algorithm, MessageType::FileHeader)
	}

	pub fn decrypt_object_header<K, M, A>(key: K, message: M, object_number: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::decrypt_message(key, message, object_number, algorithm, MessageType::ObjectHeader)
	}

	pub fn decrypt_object_footer<K, M, A>(key: K, message: M, object_number: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		Encryption::decrypt_message(key, message, object_number, algorithm, MessageType::ObjectFooter)
	}

	fn encrypt_message<K, M, A, T>(key: K, message: M, nonce_value: u64, algorithm: A, message_type: T) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
		T: Borrow<MessageType>,
	{
		let nonce = match message_type.borrow() {
			MessageType::ChunkData => Encryption::gen_crypto_nonce_chunk_data(nonce_value)?,
			MessageType::ChunkHeaderCRC32 => Encryption::gen_crypto_nonce_chunk_crc32(nonce_value)?,
			MessageType::ChunkHeaderEd25519 => Encryption::gen_crypto_nonce_chunk_ed25519_signature(nonce_value)?,
			MessageType::FileHeader => Encryption::gen_crypto_nonce_file_header(nonce_value)?,
			MessageType::FileFooter => Encryption::gen_crypto_nonce_file_footer(nonce_value)?,
			MessageType::ObjectHeader => Encryption::gen_crypto_nonce_object_header(nonce_value)?,
			MessageType::ObjectFooter => Encryption::gen_crypto_nonce_object_footer(nonce_value)?,
		};
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
		let nonce = match message_type.borrow() {
			MessageType::ChunkData => Encryption::gen_crypto_nonce_chunk_data(nonce_value)?,
			MessageType::ChunkHeaderCRC32 => Encryption::gen_crypto_nonce_chunk_crc32(nonce_value)?,
			MessageType::ChunkHeaderEd25519 => Encryption::gen_crypto_nonce_chunk_ed25519_signature(nonce_value)?,
			MessageType::FileHeader => Encryption::gen_crypto_nonce_file_header(nonce_value)?,
			MessageType::FileFooter => Encryption::gen_crypto_nonce_file_footer(nonce_value)?,
			MessageType::ObjectHeader => Encryption::gen_crypto_nonce_object_header(nonce_value)?,
			MessageType::ObjectFooter => Encryption::gen_crypto_nonce_object_footer(nonce_value)?,
		};
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


	/// encrypts the given header with the given nonce.
	/// This method should primary used to encrypt the given header.
	/// Returns a the cipthertext as ```Vec<u8>```.
	/// # Error
	/// This method will fail, if the encryption fails.
	pub(crate) fn encrypt_header<K, M, A>(key: K, message: M, nonce: &[u8; 12], algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		let nonce = Nonce::from_slice(nonce);
		match algorithm.borrow() {
			EncryptionAlgorithm::AES256GCM => {
				let cipher = Aes256Gcm::new_from_slice(key.as_ref())?;
				Ok(cipher.encrypt(nonce, message.as_ref())?)
			},
			EncryptionAlgorithm::AES128GCM => {
				let cipher = Aes128Gcm::new_from_slice(key.as_ref())?;
				Ok(cipher.encrypt(nonce, message.as_ref())?)
			},
			EncryptionAlgorithm::CHACHA20POLY1305 => {
				let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())?;
				Ok(cipher.encrypt(nonce, message.as_ref())?)
			}
		}
	}

	/// decrypts the given header with the given nonce and encryption key.
	/// This method should primary used to decrypt the given header.
	/// Returns a the plaintext as ```Vec<u8>```.
	pub(crate) fn decrypt_header<K, C, A>(key: K, ciphertext: C, nonce: &[u8; 12], algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		C: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		let nonce = Nonce::from_slice(nonce);
		match *algorithm.borrow() {
			EncryptionAlgorithm::AES256GCM => {
				let cipher = Aes256Gcm::new_from_slice(key.as_ref())?;
				Ok(cipher.decrypt(nonce, ciphertext.as_ref())?)
			},
			EncryptionAlgorithm::AES128GCM => {
				let cipher = Aes128Gcm::new_from_slice(key.as_ref())?;
				Ok(cipher.decrypt(nonce, ciphertext.as_ref())?)
			},
			EncryptionAlgorithm::CHACHA20POLY1305 => {
				let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())?;
				Ok(cipher.decrypt(nonce, ciphertext.as_ref())?)
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

	/// Method to generate a 96-bit nonce for the chunk content. Will use the chunk number as nonce and fills the
	/// missing bits with zeros.
	fn gen_crypto_nonce_chunk_data(chunk_no: u64) -> Result<Nonce> {
		let mut buffer = vec![];
		buffer.write_u64::<LittleEndian>(chunk_no)?;
		buffer.append(&mut vec!(0u8; 4));
		Ok(*Nonce::from_slice(&buffer))
	}

	/// Method to generate a 96-bit nonce for the chunk crc32 value. Will use the chunk number as nonce and fills the
	/// missing bits with zeros - except the last bit (the last bit is set).
	fn gen_crypto_nonce_chunk_crc32(chunk_no: u64) -> Result<Nonce> {
		let mut buffer = vec![];
		buffer.write_u64::<LittleEndian>(chunk_no)?;
		buffer.append(&mut vec!(0u8; 4));
		let buffer_len = buffer.len();
		buffer[buffer_len - 1] |= 0b00000001;
		Ok(*Nonce::from_slice(&buffer))
	}

	/// Method to generate a 96-bit nonce for the chunk ed25519 signature value. Will use the chunk number as nonce and fills the
	/// missing bits with zeros - except the second to last bit (will be set).
	fn gen_crypto_nonce_chunk_ed25519_signature(chunk_no: u64) -> Result<Nonce> {
		let mut buffer = vec![];
		buffer.write_u64::<LittleEndian>(chunk_no)?;
		buffer.append(&mut vec!(0u8; 4));
		let buffer_len = buffer.len();
		buffer[buffer_len - 1] |= 0b00000010;
		Ok(*Nonce::from_slice(&buffer))
	}

	/// Method to generate a 96-bit nonce for the file header. Will use the file number as nonce and fills the
	/// missing bits with zeros - except the third to last bit (will be set).
	fn gen_crypto_nonce_file_header(file_number: u64) -> Result<Nonce> {
		let mut buffer = vec![];
		buffer.write_u64::<LittleEndian>(file_number)?;
		buffer.append(&mut vec!(0u8; 4));
		let buffer_len = buffer.len();
		buffer[buffer_len - 1] |= 0b00000100;
		Ok(*Nonce::from_slice(&buffer))
	}

	/// Method to generate a 96-bit nonce for the file footer. Will use the file number as nonce and fills the
	/// missing bits with zeros - except the fourth to last bit (will be set).
	fn gen_crypto_nonce_file_footer(file_number: u64) -> Result<Nonce> {
		let mut buffer = vec![];
		buffer.write_u64::<LittleEndian>(file_number)?;
		buffer.append(&mut vec!(0u8; 4));
		let buffer_len = buffer.len();
		buffer[buffer_len - 1] |= 0b00001000;
		Ok(*Nonce::from_slice(&buffer))
	}

	/// Method to generate a 96-bit nonce for the object header. Will use the object number as nonce and fills the
	/// missing bits with zeros - except the fourth to last bit (will be set).
	fn gen_crypto_nonce_object_header(object_number: u64) -> Result<Nonce> {
		let mut buffer = vec![];
		buffer.write_u64::<LittleEndian>(object_number)?;
		buffer.append(&mut vec!(0u8; 4));
		let buffer_len = buffer.len();
		buffer[buffer_len - 1] |= 0b00010000;
		Ok(*Nonce::from_slice(&buffer))
	}

	/// Method to generate a 96-bit nonce for the object footer. Will use the object number as nonce and fills the
	/// missing bits with zeros - except the fourth to last bit (will be set).
	fn gen_crypto_nonce_object_footer(object_number: u64) -> Result<Nonce> {
		let mut buffer = vec![];
		buffer.write_u64::<LittleEndian>(object_number)?;
		buffer.append(&mut vec!(0u8; 4));
		let buffer_len = buffer.len();
		buffer[buffer_len - 1] |= 0b00100000;
		Ok(*Nonce::from_slice(&buffer))
	}
}