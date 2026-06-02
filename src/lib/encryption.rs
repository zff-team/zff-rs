// - STD
use std::fmt;

// - internal
use crate::prelude::*;

// - external
use aes::cipher::{block_padding::Pkcs7, BlockModeEncrypt, BlockModeDecrypt, KeyIvInit};
use argon2::{Config, Variant, Version, ThreadMode};
use pkcs5::{
	EncryptionScheme,
	pbes2::Parameters as PBES2Parameters,
	scrypt::Params as ScryptParams
};
use rand::Rng;
use zeroize::Zeroize;

// - types
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Defines all encryption algorithms (for use in data and header encryption), which are implemented in zff.
#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone,Eq,PartialEq, Zeroize)]
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
#[derive(Debug,Clone,Eq,PartialEq, Zeroize)]
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
#[derive(Debug,Clone,Eq,PartialEq, Zeroize)]
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

/// Generates a new random key, with the given key size.
/// # Example
/// ```no_run
/// use zff::*;
/// 
/// let keysize = 256; //(e.g. for use as 256-Bit-AES-Key).
/// let my_new_random_super_secret_key = gen_random_key(keysize);
/// //...
/// ```
pub fn gen_random_key(length: usize) -> Vec<u8> {
	let mut key = vec!(0u8; length/8);
	let mut rng = rand::rng();
	rng.fill_bytes(&mut key);
	key
}

/// Generates a new random IV/Nonce as ```[u8; 16]``` for use in PBE header.
pub fn gen_random_iv() -> [u8; 16] {
	let mut iv = [0; 16];
	let mut rng = rand::rng();
	rng.fill_bytes(&mut iv);
	iv
}

/// Generates a new random salt as ```[u8; 32]``` for use in PBE header.
pub fn gen_random_salt() -> [u8; 32] {
	let mut salt = [0; 32];
	let mut rng = rand::rng();
	rng.fill_bytes(&mut salt);
	salt
}

/// Generates a new random IV/Nonce as ```[u8; 12]``` for use in encryption header.
pub fn gen_random_header_nonce() -> [u8; 12] {
	let mut nonce = [0; 12];
	let mut rng = rand::rng();
	rng.fill_bytes(&mut nonce);
	nonce
}

/// Encrypts the given plaintext with the given values with PBKDF2-SHA256-AES128CBC, defined in PKCS#5.
/// Returns the ciphertext as ```Vec<u8>```.
/// # Error
/// if the encryption fails, or the given parameters are false.
pub fn encrypt_pbkdf2sha256_aes128cbc(
	iterations: u32,
	salt: &[u8; 32],
	aes_iv: [u8; 16],
	password: impl AsRef<[u8]>,
	plaintext: &[u8]) -> Result<Vec<u8>> {
	let params = PBES2Parameters::generate_pbkdf2_sha256_aes128cbc(iterations, salt, aes_iv)?;
	let encryption_scheme = EncryptionScheme::Pbes2(params);
	let crypt = encryption_scheme.encrypt(password, plaintext)?;
	Ok(crypt)
}

/// Encrypts the given plaintext with the given values with PBKDF2-SHA256-AES256CBC, defined in PKCS#5.
/// Returns the ciphertext as ```Vec<u8>```.
/// # Error
/// if the encryption fails, or the given parameters are false.
pub fn encrypt_pbkdf2sha256_aes256cbc(
	iterations: u32,
	salt: &[u8; 32],
	aes_iv: [u8; 16],
	password: impl AsRef<[u8]>,
	plaintext: &[u8]) -> Result<Vec<u8>> {
	let params = PBES2Parameters::generate_pbkdf2_sha256_aes256cbc(iterations, salt, aes_iv)?;
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
	aes_iv: [u8; 16],
	password: impl AsRef<[u8]>,
	ciphertext: &[u8]) -> Result<Vec<u8>> {
	let params = PBES2Parameters::generate_pbkdf2_sha256_aes128cbc(iterations, salt, aes_iv)?;
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
	aes_iv: [u8; 16],
	password: impl AsRef<[u8]>,
	ciphertext: &[u8]) -> Result<Vec<u8>> {
	let params = PBES2Parameters::generate_pbkdf2_sha256_aes256cbc(iterations, salt, aes_iv)?;
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
	aes_iv: [u8; 16],
	password: impl AsRef<[u8]>,
	plaintext: &[u8]) -> Result<Vec<u8>> {
	let params = PBES2Parameters::generate_scrypt_aes128cbc(ScryptParams::new(logn, r, p)?, salt, aes_iv)?;
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
	aes_iv: [u8; 16],
	password: impl AsRef<[u8]>,
	plaintext: &[u8]) -> Result<Vec<u8>> {
	let params = PBES2Parameters::generate_scrypt_aes256cbc(ScryptParams::new(logn, r, p)?, salt, aes_iv)?;
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
	aes_iv: [u8; 16],
	password: impl AsRef<[u8]>,
	plaintext: &[u8]) -> Result<Vec<u8>> {
	let params = PBES2Parameters::generate_scrypt_aes128cbc(ScryptParams::new(logn, r, p)?, salt, aes_iv)?;
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
	aes_iv: [u8; 16],
	password: impl AsRef<[u8]>,
	plaintext: &[u8]) -> Result<Vec<u8>> {
	let params = PBES2Parameters::generate_scrypt_aes256cbc(ScryptParams::new(logn, r, p)?, salt, aes_iv)?;
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

// hash_length is 16 for aes128cbc and 32 for aes256cbc
fn hash_password_argon2(password: &str, salt: &[u8; 32], mem_cost: u32, lanes: u32, iterations: u32, hash_length: u32) -> Result<Vec<u8>> {
    let config = Config {
	    variant: Variant::Argon2id,
	    version: Version::Version13,
	    mem_cost,
	    time_cost: iterations,
		thread_mode: ThreadMode::Parallel,
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
	let hash = match scheme {
		PBEScheme::AES128CBC => hash_password_argon2(password, salt, mem_cost, lanes, iterations, 16)?,
		PBEScheme::AES256CBC => hash_password_argon2(password, salt, mem_cost, lanes, iterations, 32)?,
	};

	match scheme {
		PBEScheme::AES128CBC => {
			let key: [u8; 16] = hash.try_into().unwrap(); // The hash length is guaranteed by hash_password_argon2, so unwrap is safe here.
			Ok(Aes128CbcEnc::new(&key.into(), aes_iv.into()).encrypt_padded_vec::<Pkcs7>(plaintext.as_ref()))
		},
		PBEScheme::AES256CBC => {
			let key: [u8; 32] = hash.try_into().unwrap(); // The hash length is guaranteed by hash_password_argon2, so unwrap is safe here.
			Ok(Aes256CbcEnc::new(&key.into(), aes_iv.into()).encrypt_padded_vec::<Pkcs7>(plaintext.as_ref()))
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
	let hash = match scheme {
		PBEScheme::AES128CBC => hash_password_argon2(password, salt, mem_cost, lanes, iterations, 16)?,
		PBEScheme::AES256CBC => hash_password_argon2(password, salt, mem_cost, lanes, iterations, 32)?,
	};

	match scheme {
		PBEScheme::AES128CBC => {
			let key: [u8; 16] = hash.try_into().unwrap(); // The hash length is guaranteed by hash_password_argon2, so unwrap is safe here.
			Ok(Aes128CbcDec::new(&key.into(), aes_iv.into()).decrypt_padded_vec::<Pkcs7>(ciphertext.as_ref())?)
		},
		PBEScheme::AES256CBC => {
			let key: [u8; 32] = hash.try_into().unwrap(); // The hash length is guaranteed by hash_password_argon2, so unwrap is safe here.
			Ok(Aes256CbcDec::new(&key.into(), aes_iv.into()).decrypt_padded_vec::<Pkcs7>(ciphertext.as_ref())?)
		},
	}
}
