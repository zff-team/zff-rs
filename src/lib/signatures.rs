// - external
use ed25519_dalek::{
	SigningKey,
	VerifyingKey,
	Signature as Ed25519Signature,
	Signer,
	Verifier,
	KEYPAIR_LENGTH,
	SECRET_KEY_LENGTH,
	PUBLIC_KEY_LENGTH
};
use rand::rngs::OsRng;
use rand::RngCore;
use base64::{Engine, engine::general_purpose::STANDARD as base64engine};

// - internal
use crate::{
	Result,
	ZffError,
	ZffErrorKind,
	ED25519_DALEK_SIGNATURE_LEN,
};


/// structure contains serveral methods to handle signing of chunked data.
pub struct Signature;

impl Signature {
	/// generates a new, random keypair.
	pub fn new_signing_key() -> SigningKey {
		let mut csprng = OsRng{};
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
			Err(ZffError::new(ZffErrorKind::WrongSignatureKeyLength, ""))
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
			Err(ZffError::new(ZffErrorKind::WrongSignatureKeyLength, ""))
		}
	}

	/// sign the data with the given signing key.
	pub fn sign(signing_key: &SigningKey, message: &[u8]) -> [u8; ED25519_DALEK_SIGNATURE_LEN] {
		let signature = signing_key.sign(message);
		signature.to_bytes()
	}

	/// verify the data with the given base64 encoded key (signing key or verifying keys are possible to use here).
	pub fn verify_with_base64_key<K: Into<String>>(key: K, message: &[u8], signature: [u8; ED25519_DALEK_SIGNATURE_LEN]) -> Result<bool> {
		let key = base64engine.decode(key.into())?;
		Signature::verify(key, message, signature)
	}

	/// verify the data with the given key bytes (signing key or verifying keys are possible to use here).
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
			return Err(ZffError::new(ZffErrorKind::WrongSignatureKeyLength, ""));
		};
		let signature = Ed25519Signature::from_bytes(&signature);
		match verifying_key.verify(message, &signature) {
			Ok(_) => Ok(true),
			Err(_) => Ok(false),
		}
	}
}