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

#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone)]
pub enum EncryptionAlgorithm {
	AES128GCMSIV = 0,
	AES256GCMSIV = 1,
}

#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone)]
pub enum KDFScheme {
	PBKDF2SHA256 = 0,
}

//TODO: Migrate to enum EncryptionAlgorithm
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone)]
pub enum PBEScheme {
	AES128CBC = 0,
	AES256CBC = 1,
}

pub struct Encryption;

impl Encryption {
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

	pub fn encrypt_pbkdf2sha256_aes256cbc(
		iterations: u16,
		salt: &[u8; 32],
		aes_iv: &[u8; 16],
		password: impl AsRef<[u8]>,
		plaintext: &[u8]) -> Result<Vec<u8>> {
		let params = PBES2Parameters::pbkdf2_sha256_aes256cbc(iterations, salt, aes_iv)?;
		let encryption_scheme = EncryptionScheme::Pbes2(params);
		Ok(encryption_scheme.encrypt(password, plaintext)?)
	}

	/// method to encrypt a message with a key and nonce.
	/// # Example
	///	```
	/// use zff::*;
	/// use phollaits::ToHex;
	///
	/// fn main() -> Result<()> {
	///		let key = "01234567890123456789012345678912"; // 32Byte/256Bit Key
	///		let chunk_no = 1; // 12Byte/96Bit Key
	///		let message = "My message";
	/// 
	///		let ciphertext = Encryption::encrypt_message(key, message, chunk_no, EncryptionAlgorithm::AES256GCMSIV)?;
	/// 
	///		assert_eq!(ciphertext.hexify(), "32f1c2f8ff6594a07eda5a4eca6d198f4cda8935f171d2345888".to_string());
	///		Ok(())
	/// }
	///	```
	pub fn encrypt_message<K, M>(key: K, message: M, chunk_no: u64, algorithm: &EncryptionAlgorithm) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
	{
		let nonce = Encryption::sector_as_crypto_nonce(chunk_no)?;
		match algorithm {
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

	pub fn encrypt_header<K, M>(key: K, message: M, nonce: [u8; 12], algorithm: &EncryptionAlgorithm) -> Result<Vec<u8>>
	where
		K: AsRef<[u8]>,
		M: AsRef<[u8]>,
	{
		let nonce = Nonce::from_slice(&nonce);
		match algorithm {
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

	pub fn gen_random_key(length: usize) -> Vec<u8> {
		let mut key = vec!(0u8; length/8);
		let mut rng = OsRng;
		rng.fill_bytes(&mut key);
		key
	}

	pub fn gen_random_iv() -> [u8; 16] {
		let mut iv = [0; 16];
		let mut rng = OsRng;
		rng.fill_bytes(&mut iv);
		iv
	}

	pub fn gen_random_salt() -> [u8; 32] {
		let mut salt = [0; 32];
		let mut rng = OsRng;
		rng.fill_bytes(&mut salt);
		salt
	}

	pub fn gen_random_header_nonce() -> [u8; 12] {
		let mut nonce = [0; 12];
		let mut rng = OsRng;
		rng.fill_bytes(&mut nonce);
		nonce
	}

	fn sector_as_crypto_nonce(sector_no: u64) -> Result<Nonce> {
		let mut buffer = vec![];
		buffer.write_u64::<LittleEndian>(sector_no)?;
		buffer.append(&mut vec!(0u8; 4));
		Ok(*Nonce::from_slice(&buffer))
	}
}