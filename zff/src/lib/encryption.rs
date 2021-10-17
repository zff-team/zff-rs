// - STD
use std::borrow::Borrow;

// - internal
use crate::{
	Result,
};

// - external
use pkcs5::{
	EncryptionScheme,
	pbes2::Parameters as PBES2Parameters,
};
use aes_gcm_siv::{
	Aes256GcmSiv, Aes128GcmSiv, Nonce, Key,
	aead::{Aead, NewAead},
};
use byteorder::{LittleEndian, WriteBytesExt};
use rand::{rngs::OsRng, RngCore};
use serde::{Serialize};

/// Defines all encryption algorithms (for use in data and header encryption), which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Serialize)]
pub enum EncryptionAlgorithm {
	/// AES (128-Bit) in Galois/Counter Mode operation with misuse resistance in the event of the reuse of a cryptographic nonce.\
	/// Encoded with value 0.
	AES128GCMSIV = 0,
	/// AES (256-Bit) in Galois/Counter Mode operation with misuse resistance in the event of the reuse of a cryptographic nonce.\
	/// Encoded with value 1.
	AES256GCMSIV = 1,
}

/// Defines all KDF schemes, which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Serialize)]
pub enum KDFScheme {
	/// KDF scheme PBKDF2-SHA256, with encoding value 0.
	PBKDF2SHA256 = 0,
}

/// Defines all encryption algorithms (for use in PBE only!), which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Serialize)]
pub enum PBEScheme {
	/// AES128-CBC encryption scheme used in pbe with the encoding value 0.
	AES128CBC = 0,
	/// AES128-CBC encryption scheme used in pbe with the encoding value 1.
	AES256CBC = 1,
}

/// structure contains serveral methods to handle encryption
pub struct Encryption;

impl Encryption {
	/// encrypts the given plaintext with the given values with PBKDF2-SHA256-AES128CBC, defined in PKCS#5.
	/// Returns the ciphertext as ```Vec<u8>```.
	/// # Error
	/// if the encryption fails, or the given parameters are false.
	pub fn encrypt_pbkdf2sha256_aes128cbc(
		iterations: u16,
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
		iterations: u16,
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
		iterations: u16,
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
		iterations: u16,
		salt: &[u8; 32],
		aes_iv: &[u8; 16],
		password: impl AsRef<[u8]>,
		ciphertext: &[u8]) -> Result<Vec<u8>> {
		let params = PBES2Parameters::pbkdf2_sha256_aes256cbc(iterations, salt, aes_iv)?;
		let encryption_scheme = EncryptionScheme::Pbes2(params);
		Ok(encryption_scheme.decrypt(password, ciphertext)?)
	}

	/// method to encrypt a message with a key and and the given chunk number. This method should primary used to encrypt
	/// the given chunk data (if selected, then **after the compression**).
	/// Returns a the cipthertext as ```Vec<u8>```.
	/// # Example
	///	```
	/// use zff::*;
	/// use hex::ToHex;
	///
	/// fn main() -> Result<()> {
	///		let key = "01234567890123456789012345678912"; // 32Byte/256Bit Key
	///		let chunk_no = 1; // 12Byte/96Bit Key
	///		let message = "My message";
	/// 
	///		let ciphertext = Encryption::encrypt_message(key, message, chunk_no, EncryptionAlgorithm::AES256GCMSIV)?;
	/// 
	///		assert_eq!(ciphertext.encode_hex::<String>(), "32f1c2f8ff6594a07eda5a4eca6d198f4cda8935f171d2345888".to_string());
	///		Ok(())
	/// }
	///	```
	/// # Error
	/// This method will fail, if the encryption fails.
	pub fn encrypt_message<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		let nonce = Encryption::chunk_as_crypto_nonce(chunk_no)?;
		match algorithm.borrow() {
			EncryptionAlgorithm::AES256GCMSIV => {
				let cipher = Aes256GcmSiv::new(Key::from_slice(key.as_ref()));
				return Ok(cipher.encrypt(&nonce, message.as_ref())?);
			},
			EncryptionAlgorithm::AES128GCMSIV => {
				let cipher = Aes128GcmSiv::new(Key::from_slice(key.as_ref()));
				return Ok(cipher.encrypt(&nonce, message.as_ref())?);
			},
		};
	}

	/// method to decrypt a message with a key and and the given chunk number. This method should primary used to decrypt
	/// the given chunk data (if selected, then **before the decompression**).
	/// Returns a the plaintext as ```Vec<u8>``` of the given ciphertext.
	/// # Error
	/// This method will fail, if the decryption fails.
	pub fn decrypt_message<K, M, A>(key: K, message: M, chunk_no: u64, algorithm: A) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
		A: Borrow<EncryptionAlgorithm>,
	{
		let nonce = Encryption::chunk_as_crypto_nonce(chunk_no)?;
		match algorithm.borrow() {
			EncryptionAlgorithm::AES256GCMSIV => {
				let cipher = Aes256GcmSiv::new(Key::from_slice(key.as_ref()));
				return Ok(cipher.decrypt(&nonce, message.as_ref())?);
			},
			EncryptionAlgorithm::AES128GCMSIV => {
				let cipher = Aes128GcmSiv::new(Key::from_slice(key.as_ref()));
				return Ok(cipher.decrypt(&nonce, message.as_ref())?);
			},
		};
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
			EncryptionAlgorithm::AES256GCMSIV => {
				let cipher = Aes256GcmSiv::new(Key::from_slice(key.as_ref()));
				return Ok(cipher.encrypt(nonce, message.as_ref())?);
			},
			EncryptionAlgorithm::AES128GCMSIV => {
				let cipher = Aes128GcmSiv::new(Key::from_slice(key.as_ref()));
				return Ok(cipher.encrypt(nonce, message.as_ref())?);
			},
		};
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
			EncryptionAlgorithm::AES256GCMSIV => {
				let cipher = Aes256GcmSiv::new(Key::from_slice(key.as_ref()));
				return Ok(cipher.decrypt(nonce, ciphertext.as_ref())?);
			},
			EncryptionAlgorithm::AES128GCMSIV => {
				let cipher = Aes128GcmSiv::new(Key::from_slice(key.as_ref()));
				return Ok(cipher.decrypt(nonce, ciphertext.as_ref())?);
			},
		};
	}

	/// Generates a new random key, with the given key size.
	/// # Example
	/// ```no_run
	/// use zff::*;
	/// 
	/// fn main() {
	/// 	let keysize = 256; //(e.g. for use as 256-Bit-AES-Key).
	/// 	let my_new_random_super_secret_key = Encryption::gen_random_key(keysize);
	/// 	//...
	/// }
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

	fn chunk_as_crypto_nonce(chunk_no: u64) -> Result<Nonce> {
		let mut buffer = vec![];
		buffer.write_u64::<LittleEndian>(chunk_no)?;
		buffer.append(&mut vec!(0u8; 4));
		Ok(*Nonce::from_slice(&buffer))
	}
}