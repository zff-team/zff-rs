//! Trait for encryption operations in zff.
//!
//! This module provides the [`Encryption`] trait which defines the interface for
//! encrypting and decrypting data using various encryption algorithms.

// - STD
use std::borrow::Borrow;

// - internal
use crate::{EncryptionAlgorithm, Nonce, Result};

// - external
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, aead::Aead};
use byteorder::{LittleEndian, WriteBytesExt};
use chacha20poly1305::ChaCha20Poly1305;

/// trait to implement the zff encryption for the appropriate type.
pub trait Encryption {
    /// Encrypts the message, using the type specific nonce padding.
    fn encrypt<K, M, A>(key: K, message: M, nonce_value: u64, algorithm: A) -> Result<Vec<u8>>
    where
        K: AsRef<[u8]>,
        M: AsRef<[u8]>,
        A: Borrow<EncryptionAlgorithm>,
    {
        let nonce = Self::gen_crypto_nonce(nonce_value)?;

        match algorithm.borrow() {
            EncryptionAlgorithm::AES256GCM => {
                let cipher = Aes256Gcm::new_from_slice(key.as_ref())?;
                Ok(cipher.encrypt(&nonce, message.as_ref())?)
            }
            EncryptionAlgorithm::AES128GCM => {
                let cipher = Aes128Gcm::new_from_slice(key.as_ref())?;
                Ok(cipher.encrypt(&nonce, message.as_ref())?)
            }
            EncryptionAlgorithm::CHACHA20POLY1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())?;
                Ok(cipher.encrypt(&nonce, message.as_ref())?)
            }
        }
    }

    /// Decrypts the message, using the type specific nonce padding.
    fn decrypt<K, M, A>(key: K, message: M, nonce_value: u64, algorithm: A) -> Result<Vec<u8>>
    where
        K: AsRef<[u8]>,
        M: AsRef<[u8]>,
        A: Borrow<EncryptionAlgorithm>,
    {
        let nonce = Self::gen_crypto_nonce(nonce_value)?;
        match algorithm.borrow() {
            EncryptionAlgorithm::AES256GCM => {
                let cipher = Aes256Gcm::new_from_slice(key.as_ref())?;
                Ok(cipher.decrypt(&nonce, message.as_ref())?)
            }
            EncryptionAlgorithm::AES128GCM => {
                let cipher = Aes128Gcm::new_from_slice(key.as_ref())?;
                Ok(cipher.decrypt(&nonce, message.as_ref())?)
            }
            EncryptionAlgorithm::CHACHA20POLY1305 => {
                let cipher = ChaCha20Poly1305::new_from_slice(key.as_ref())?;
                Ok(cipher.decrypt(&nonce, message.as_ref())?)
            }
        }
    }

    /// Method to generate a 96-bit nonce for the appropriate message type (using the given value).
    fn gen_crypto_nonce(nonce_value: u64) -> Result<Nonce> {
        let mut buffer = vec![];
        buffer.write_u64::<LittleEndian>(nonce_value)?;
        buffer.append(&mut vec![0u8; 4]);
        let buffer_len = buffer.len();
        buffer[buffer_len - 1] |= Self::crypto_nonce_padding();
        Ok(Nonce::try_from(buffer.as_slice())?)
    }

    /// The appropriate, type specific padding value for the nonce (see official zff documentation).
    fn crypto_nonce_padding() -> u8;
}
