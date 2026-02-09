#![forbid(unsafe_code)]
#![deny(missing_docs)]
//#![deny(warnings)]
//! This crate provides the reference implementation of the forensic file format Zff.
//! Zff is a new file format for forensic images, as an alternative to EWF and AFF.
//! Zff is focused on speed and security. If you want to learn more about ZFF, visit [https://github.com/ph0llux/zff](https://github.com/ph0llux/zff).

// adds #![feature(windows_by_handle)] to the crate for windows platforms only.
#![cfg_attr(target_os = "windows", feature(windows_by_handle))]

// - STD
use std::borrow::Borrow;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, TryReserveError, VecDeque};
use std::io::{Read, Seek, SeekFrom, copy as io_copy, Cursor, Write};
use std::fmt;
use std::string::FromUtf8Error;
use std::num::ParseIntError;
use std::sync::{
    Arc,
    RwLock, RwLockReadGuard,
};
use std::thread::{self};
use std::time::SystemTime;
use std::rc::Rc;
use std::cell::RefCell;
use std::path::{PathBuf, Path};
#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_family = "unix")]
use std::os::unix::fs::FileTypeExt;
#[cfg(target_family = "unix")]
use std::fs::metadata;
use std::cmp::PartialEq;
use std::fs::{Metadata, OpenOptions, read_dir, read_link};
use std::thread::sleep;
use std::time::Duration;
use std::ops::{Add, AddAssign};

// - modules
/// This module contains all constants, used in this crate.
pub mod constants;
/// This module contains all header, could be found in the zff specification (header version 1 and header version 2).
pub mod header;
/// This module contains all footer, could be found in the zff specification (footer version 1 and footer version 2).
pub mod footer;
/// Contains several stuff to handle zff container (e.g. create, extend or read zff container).
pub mod io;
/// Contains some little helper functions
pub mod helper;
mod hashing;
mod compression;
/// Contains various functions, methods and traits to handle encryption in zff.
pub mod encryption;
mod traits;
mod error;
mod signatures;
mod file_extension;
mod object;
mod file;
mod segment;
mod chunk;

// - re-exports
pub use hashing::*;
pub use compression::*;
pub use encryption::*;
pub use error::*;
pub use signatures::*;
pub use traits::*;
pub use file_extension::*;
use constants::*;
pub use object::*;
pub use file::*;
pub use segment::*;
pub use chunk::*;

// - types
/// Result for std::result::Result<T, ZffError>.
pub type Result<T> = std::result::Result<T, ZffError>;
type Nonce = AesGcmNonce<U12>; //use the (by NIST) recommended nonce size of 96-bit.

// - external
use std::any::Any;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use aes_gcm::{
	Aes256Gcm, Aes128Gcm, Nonce as AesGcmNonce, KeyInit,
	aead::Aead,
};
use argon2::{Config, Variant, Version, ThreadMode};

use base64::{Engine, engine::general_purpose::STANDARD as base64engine};
use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use blake2::Blake2b512;
use blake3::{Hasher as Blake3, Hash as Blake3Hash};
use chacha20poly1305::ChaCha20Poly1305;
use digest::{DynDigest, Digest};
use ed25519_dalek::{
	SigningKey,
	VerifyingKey,
	Signature as Ed25519Signature,
	Signer,
	Verifier,
	KEYPAIR_LENGTH,
	SECRET_KEY_LENGTH,
    SIGNATURE_LENGTH,
	PUBLIC_KEY_LENGTH
};
use itertools::Itertools;
use ordered_float::OrderedFloat;
use pkcs5::{
	EncryptionScheme,
	pbes2::Parameters as PBES2Parameters,
	scrypt::Params as ScryptParams
};
use rand::{rng, RngCore, rngs::StdRng, SeedableRng};
use redb::{Database, ReadableDatabase, TableDefinition};
use sha2::{Sha256, Sha512};
use sha3::Sha3_256;
use typenum::consts::U12;
use xxhash_rust::xxh3::xxh3_64;

// - external-errortypes
use pkcs5::Error as PKCS5CryptoError;
use pkcs5::scrypt::errors::InvalidParams as ScryptErrorInvalidParams;
use aes_gcm::aead::Error as AesError;
use digest::InvalidLength;
use ed25519_dalek::ed25519::Error as Ed25519Error;
use base64::DecodeError as Base64DecodingError;
use lz4_flex::frame::Error as Lz4Error;
use time::error::ComponentRange as ComponentRangeError;
use redb::{
	DatabaseError as RedbError, 
	TransactionError as RedbTransactionError, 
	TableError as RedbTableError, 
	StorageError as RedbStorageError,
	CommitError as RedbCommitError
	};
use argon2::Error as Argon2Error;
use cbc::cipher::block_padding::UnpadError as AesCbcError;

#[cfg(target_family = "unix")]
use time::OffsetDateTime;
#[cfg(target_family = "unix")]
use posix_acl::{PosixACL, Qualifier, ACLEntry};
#[cfg(target_family = "unix")]
use xattr::XAttrs;
#[cfg(target_family = "windows")]
use std::os::windows::fs::MetadataExt;

#[cfg(feature = "log")]
use log::{debug, info, warn, trace};
#[cfg(feature = "serde")]
use hex::FromHex;
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize, ser::{Serializer, SerializeStruct, SerializeMap, SerializeSeq}};