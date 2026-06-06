//! Module for digital signature operations in zff.
//!
//! This module provides functionality for creating and verifying digital signatures
//! using the Ed25519 algorithm. Signatures are used to authenticate data integrity
//! and ensure non-repudiation in zff containers.
//!
//! # Types
//!
//! - [`Signature`]: Structure containing methods for signature operations
//!
//! # Features
//!
//! - Ed25519 signature generation and verification
//! - Key generation and parsing (including base64-encoded keys)
//! - Support for both secret keys and keypairs

// - STD

// - internal
use crate::prelude::*;

// - external
use base64::{Engine, engine::general_purpose::STANDARD as base64engine};
use ed25519_dalek::{
	Signature as Ed25519Signature,
	Signer,
	SigningKey,
	Verifier,
	VerifyingKey,
	KEYPAIR_LENGTH,
	PUBLIC_KEY_LENGTH,
	SECRET_KEY_LENGTH,
};
use rand::Rng;


/// structure contains several methods to handle signing of chunked data.
///
/// # Example
/// ```no_run
/// use zff::Signature;
///
/// // Generate a new signing key
/// let signing_key = Signature::new_signing_key();
/// // Use this key to sign data
/// // let signature = Signature::sign(&signing_key, &data);
/// ```
pub struct Signature;

impl Signature {
	/// generates a new, random keypair.
	///
	/// # Example
	/// ```no_run
	/// use zff::Signature;
	///
	/// // Generate a new Ed25519 signing key
	/// let signing_key = Signature::new_signing_key();
	/// // This key can be used to sign data
	/// ```
	pub fn new_signing_key() -> SigningKey {
		let mut csprng = rand::rng();
		let mut secret_key = [0u8; SECRET_KEY_LENGTH];
		csprng.fill_bytes(&mut secret_key);
		SigningKey::from_bytes(&secret_key)
	}

	/// returns a signingkey, parsed from the input data (formatted as base64).\
	/// Input data can be a secret key (32 bytes) or a secret/public keypair (64 bytes).
	pub fn new_signingkey_from_base64<K: Into<String>>(key: K) -> Result<SigningKey> {
		//decodes the base64 content.
		let key = base64engine.decode(key.into())?;
		// check if the content is a keypair or a secret key
		if key.len() == KEYPAIR_LENGTH {
			let mut key_slice = [0u8; KEYPAIR_LENGTH];
			key_slice.copy_from_slice(&key);
			Ok(SigningKey::from_keypair_bytes(&key_slice)?)
		} else if key.len() == SECRET_KEY_LENGTH {
			let mut key_slice = [0u8; SECRET_KEY_LENGTH];
			key_slice.copy_from_slice(&key);
			Ok(SigningKey::from_bytes(&key_slice))
		} else {
			Err(ZffError::new(ZffErrorKind::SigningError, ERROR_WRONG_SIGNATURE_KEY_LENGTH))
		}
	}

	/// Converts bytes of a secret key or a keypair into a SigningKey
	pub fn bytes_to_signingkey<K: AsRef<[u8]>>(key: K) -> Result<SigningKey> {
		let key = key.as_ref();
		// check if the content is a keypair or a secret key
		if key.len() == KEYPAIR_LENGTH {
			let mut key_slice = [0u8; KEYPAIR_LENGTH];
			key_slice.copy_from_slice(key);
			Ok(SigningKey::from_keypair_bytes(&key_slice)?)
		} else if key.len() == SECRET_KEY_LENGTH {
			let mut key_slice = [0u8; SECRET_KEY_LENGTH];
			key_slice.copy_from_slice(key);
			Ok(SigningKey::from_bytes(&key_slice))
		} else {
			Err(ZffError::new(ZffErrorKind::SigningError, ERROR_WRONG_SIGNATURE_KEY_LENGTH))
		}
	}

	/// sign the data with the given signing key.
	///
	/// # Example
	/// ```no_run
	/// use zff::Signature;
	///
	/// // Generate a signing key
	/// let signing_key = Signature::new_signing_key();
	/// // Sign some data
	/// let message = b"Important forensic data";
	/// let signature = Signature::sign(&signing_key, message);
	/// // signature is a [u8; 64] array (Ed25519 signature)
	/// ```
	pub fn sign(signing_key: &SigningKey, message: &[u8]) -> [u8; ED25519_DALEK_SIGNATURE_LEN] {
		let signature = signing_key.sign(message);
		signature.to_bytes()
	}

	/// verify the data with the given base64 encoded key (signing key or verifying keys are possible to use here).
	///
	/// # Example
	/// ```no_run
	/// use zff::Signature;
	///
	/// // Base64 encoded key (could be a signing key or verifying key)
	/// let base64_key = "base64_encoded_key_here";
	/// let message = b"Signed data";
	/// let signature: [u8; 64] = [0; 64]; // actual signature bytes
	/// let is_valid = Signature::verify_with_base64_key(base64_key, message, signature).unwrap();
	/// ```
	pub fn verify_with_base64_key<K: Into<String>>(key: K, message: &[u8], signature: [u8; ED25519_DALEK_SIGNATURE_LEN]) -> Result<bool> {
		let key = base64engine.decode(key.into())?;
		Signature::verify(key, message, signature)
	}

	/// verify the data with the given key bytes (signing key or verifying keys are possible to use here).
	///
	/// # Example
	/// ```no_run
	/// use zff::Signature;
	///
	/// // Key bytes (could be a signing key keypair (64 bytes) or verifying key (32 bytes))
	/// let key_bytes: Vec<u8> = vec![0; 32]; // actual key bytes
	/// let message = b"Signed data";
	/// let signature: [u8; 64] = [0; 64]; // actual signature bytes
	/// let is_valid = Signature::verify(&key_bytes, message, signature).unwrap();
	/// assert!(is_valid); // or false if signature is invalid
	/// ```
	/// # Error
	/// if the verification fails, or the given parameters are false.
	pub fn verify<K>(key: K, message: &[u8], signature: [u8; ED25519_DALEK_SIGNATURE_LEN]) -> Result<bool> 
	where
		K: AsRef<[u8]>
	{
		let key = key.as_ref();
		// check if the content is a signing key, a secret key or a verifying key.
		let verifying_key = if key.len() == KEYPAIR_LENGTH { // if the key is a signing key
			let mut key_slice = [0u8; KEYPAIR_LENGTH];
			key_slice.copy_from_slice(key);
			let sign_key = SigningKey::from_keypair_bytes(&key_slice)?;
			sign_key.verifying_key()
		} else if key.len() == PUBLIC_KEY_LENGTH {
			let mut key_slice = [0u8; PUBLIC_KEY_LENGTH];
			key_slice.copy_from_slice(key);
			VerifyingKey::from_bytes(&key_slice)?
		} else {
			return Err(ZffError::new(ZffErrorKind::SigningError,ERROR_WRONG_SIGNATURE_KEY_LENGTH));
		};
		let signature = Ed25519Signature::from_bytes(&signature);
		match verifying_key.verify(message, &signature) {
			Ok(_) => Ok(true),
			Err(_) => Ok(false),
		}
	}
}