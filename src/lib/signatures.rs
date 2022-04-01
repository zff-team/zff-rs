// - external
use ed25519_dalek::{
	Keypair,
	SecretKey,
	PublicKey,
	Signature as Ed25519Signature,
	Signer,
	Verifier,
	KEYPAIR_LENGTH,
	SECRET_KEY_LENGTH,
};
use rand::rngs::OsRng;

// - internal
use crate::{
	Result,
	ZffError,
	ZffErrorKind,
	ED25519_DALEK_SIGNATURE_LEN,
	ED25519_DALEK_PUBKEY_LEN,
};

/// structure contains serveral methods to handle signing of chunked data.
pub struct Signature;

impl Signature {
	/// generates a new, random keypair.
	pub fn new_keypair() -> Keypair {
		let mut csprng = OsRng{};
		Keypair::generate(&mut csprng)
	}

	/// returns a keypair, parsed from the input data (formatted as base64).\
	/// Input data can be a secret key (32 bytes) or a secret/public keypair (64 bytes).
	pub fn new_keypair_from_base64<K: Into<String>>(key: K) -> Result<Keypair> {
		let key = base64::decode(&key.into())?;
		if key.len() == KEYPAIR_LENGTH {
			Ok(Keypair::from_bytes(&key)?)
		} else if key.len() == SECRET_KEY_LENGTH {
			let sec_key = SecretKey::from_bytes(&key)?;
			let pub_key: PublicKey = (&sec_key).into();
			let mut keypair_bytes = Vec::new();
			keypair_bytes.append(&mut key.to_vec());
			keypair_bytes.append(&mut pub_key.to_bytes().to_vec());
			Ok(Keypair::from_bytes(&keypair_bytes)?)
		} else {
			Err(ZffError::new(ZffErrorKind::WrongSignatureKeyLength, ""))
		}
	}

	/// sign the data with the given keypair bytes.
	pub fn sign(keypair: &Keypair, message: &[u8]) -> [u8; ED25519_DALEK_SIGNATURE_LEN] {
		let signature = keypair.sign(message);
		signature.to_bytes()
	}

	/// verify the data with the given public key bytes.
	pub fn verify(publickey: [u8; ED25519_DALEK_PUBKEY_LEN], message: &[u8], signature: [u8; ED25519_DALEK_SIGNATURE_LEN]) -> Result<bool> {
		let pub_key = PublicKey::from_bytes(&publickey)?;
		let signature = Ed25519Signature::from_bytes(&signature)?;
		match pub_key.verify(message, &signature) {
			Ok(_) => Ok(true),
			Err(_) => Ok(false),
		}
	}
}

/// The signature flags used in zff.
#[derive(Debug,Clone)]
pub enum SignatureFlag {
	/// No signature method was used.
	NoSignatures = 0,
	/// The hash values will be signed only.
	HashValueSignatureOnly = 1,
	/// Every individual chunk and the hash values will be signed.
	PerChunkSignatures = 2,
}