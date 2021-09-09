// - external
use ed25519_dalek::{
	Keypair,
	SecretKey,
	PublicKey,
	Signature as Ed25519Signature,
	Signer,
	Verifier,
	KEYPAIR_LENGTH,
	SIGNATURE_LENGTH,
	PUBLIC_KEY_LENGTH,
	SECRET_KEY_LENGTH,
};
use rand::rngs::OsRng;

// - internal
use crate::{
	Result,
	ZffError,
	ZffErrorKind,
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
			return Ok(Keypair::from_bytes(&key)?);
		} else if key.len() == SECRET_KEY_LENGTH {
			let sec_key = SecretKey::from_bytes(&key)?;
			let pub_key: PublicKey = (&sec_key).into();
			let mut keypair_bytes = Vec::new();
			keypair_bytes.append(&mut key.to_vec());
			keypair_bytes.append(&mut pub_key.to_bytes().to_vec());
			return Ok(Keypair::from_bytes(&keypair_bytes)?);
		} else {
			return Err(ZffError::new(ZffErrorKind::WrongSignatureKeyLength, ""));
		}
	}

	/// sign the data with the given keypair bytes.
	pub fn sign(keypair_bytes: [u8; KEYPAIR_LENGTH], message: &[u8]) -> Result<[u8; SIGNATURE_LENGTH]> {
		let keypair = Keypair::from_bytes(&keypair_bytes)?;
		let signature = keypair.sign(&message);
		Ok(signature.to_bytes())
	}

	/// verify the data with the given public key bytes.
	pub fn verify(publickey: [u8; PUBLIC_KEY_LENGTH], message: &[u8], signature: [u8; SIGNATURE_LENGTH]) -> Result<bool> {
		let pub_key = PublicKey::from_bytes(&publickey)?;
		let signature = Ed25519Signature::new(signature);
		match pub_key.verify(message, &signature) {
			Ok(_) => return Ok(true),
			Err(_) => return Ok(false),
		}
	}
}