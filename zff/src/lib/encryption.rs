// - internal
use crate::{
	Result,
};

// - external
use pkcs5::{
	EncryptionScheme,
	pbes2::Parameters as PBES2Parameters,
};
use aes_gcm_siv::Nonce;
use byteorder::{LittleEndian, WriteBytesExt};

pub struct Encryption;

impl Encryption {
	pub fn pbkdf2sha256_aes128cbc(
		iterations: u16,
		salt: &[u8; 32],
		aes_iv: &[u8; 16],
		password: impl AsRef<[u8]>,
		plaintext: &[u8]) -> Result<Vec<u8>> {
		let params = PBES2Parameters::pbkdf2_sha256_aes128cbc(iterations, salt, aes_iv)?;
		let encryption_scheme = EncryptionScheme::Pbes2(params);
		Ok(encryption_scheme.encrypt(password, plaintext)?)
	}

	pub fn sector_as_crypto_nonce(sector_no: u64) -> Result<Nonce> {
		let mut buffer = vec![];
		buffer.write_u64::<LittleEndian>(sector_no)?;
		buffer.append(&mut vec!(0u8; 4));
		Ok(*Nonce::from_slice(&buffer))
	}
}