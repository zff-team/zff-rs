// - STD
use std::sync::{
    Arc,
    RwLock, RwLockReadGuard,
};
use std::collections::HashMap;
use std::thread;
use std::io::copy as io_copy;

// - modules
mod encoder; 

// - re-exports
pub use encoder::*;

// - internal
use crate::{
    Result,
	HeaderCoding,
    header::CompressionHeader,
    HashType,
    Hash,
    CompressionAlgorithm,
    io::{buffer_chunk, check_same_byte},
	header::{ChunkHeader, DeduplicationChunkMap},
	error::{ZffError, ZffErrorKind},
	encryption::{Encryption, EncryptionAlgorithm},
	ChunkContent,
};

/// creates a EncodingThreadPoolManager which contains a HashingThreadManager and a CompressionThread and a Crc32Thread.
/// The EncodingThreadPoolManager is used to manage the threads and to ensure that the threads will use the given data in zero-copy way.
pub struct EncodingThreadPoolManager {
    /// the hashing threads.
    hashing_threads: HashingThreadManager,
    /// the compression thread.
    compression_thread: CompressionThread,
    /// the crc32 thread.
    crc32_thread: Crc32Thread,
	/// the same bytes thread.
	same_bytes_thread: SameBytesThread,
    /// the data, which will be used by the appropriate threads.
    pub data: Arc<RwLock<Vec<u8>>>, 
}

impl EncodingThreadPoolManager {
    /// creates a new ThreadPoolManager with the given number of hashing threads.
    pub fn new(compression_header: CompressionHeader, chunk_size: usize) -> Self {
        let data = Arc::new(RwLock::new(Vec::new()));
        let hashing_thread_manager = HashingThreadManager::new(Arc::clone(&data));
        Self {
            hashing_threads: hashing_thread_manager,
            compression_thread: CompressionThread::new(compression_header, chunk_size, Arc::clone(&data)),
			same_bytes_thread: SameBytesThread::new(Arc::clone(&data)),
            crc32_thread: Crc32Thread::new(Arc::clone(&data)),
            data,
        }
    }

    /// adds a new hashing thread to the underlying ThreadPoolManager.
    pub fn add_hashing_thread(&mut self, hash_type: HashType) {
        self.hashing_threads.add_thread(hash_type);
    }

    /// updates the data of the hashing threads.
    pub fn update(&self, data: Vec<u8>) {
        let mut w = self.data.write().unwrap();
        *w = data;
    }

	/// finalizes all hashing threads and returns a HashMap<HashType, Vec<u8>> with the appropriate hash values.
	pub fn finalize_all_hashing_threads(&mut self) -> HashMap<HashType, Vec<u8>> {
		self.hashing_threads.finalize_all()
	}

    /// triggers the underlying HashingThreadManager, the CompressionThread and the Crc32Thread to continue processes with the updated data field.
    /// This function should be called after the data field was updated.
    pub fn trigger(&mut self) {
		self.same_bytes_thread.trigger();
        self.compression_thread.trigger();
        self.crc32_thread.trigger();
		self.hashing_threads.trigger();
    }
}

/// Structure to manage the HashingThreads and ensures that the threads will use the given data in zero-copy way.
#[derive(Debug)]
pub(crate) struct HashingThreadManager {
	/// the hashing threads.
	pub threads: HashMap<HashType, HashingThread>,
	/// a separate hashing thread for deduplication hashing.
	pub deduplication_thread: Option<DeduplicationThread>,
	/// the data, which will be used by the hashing threads.
	pub data: Arc<RwLock<Vec<u8>>>,
}

impl HashingThreadManager {
	/// creates a new HashingThreadManager without any hashing threads.
	pub fn new(data: Arc<RwLock<Vec<u8>>>) -> Self {
		Self {
			threads: HashMap::new(),
			deduplication_thread: None,
			data,
		}
	}

	/// creates a new HashingThread by using the given HashType.
	pub fn add_thread(&mut self, hash_type: HashType) {
		if self.threads.get(&hash_type).is_none() {
			self.threads.insert(hash_type.clone(), HashingThread::new(hash_type, self.data.clone()));
		}
	}

	/// adds a new deduplication thread.
	pub fn add_deduplication_thread(&mut self) {
		if self.deduplication_thread.is_none() {
			self.deduplication_thread = Some(DeduplicationThread::new(self.data.clone()));
		}
	}

	/// returns the deduplication result. Adds a new deduplication thread and - in this case - 
	/// triggers the appropriate thread to continue, if the thread not exists.
	pub fn get_deduplication_result(&mut self) -> blake3::Hash {
		if self.deduplication_thread.is_none() {
			self.add_deduplication_thread();
			self.deduplication_thread.as_ref().unwrap().trigger();
		}
		self.deduplication_thread.as_ref().unwrap().get_result()
	}

	/// triggers all hashing threads to continue the hashing process with the updated data field.
	/// This function should be called after the data field was updated.
	pub fn trigger(&mut self) {
		// blocks a read on the RwLock to ensure that the threads will use valid data.
		let a = self.data.read().unwrap();

		for thread in self.threads.values_mut() {
			thread.trigger();
		}
		// trigger the deduplication thread (if exists)
		if let Some(thread) = &self.deduplication_thread {
			thread.trigger();
		}

		drop(a);
	}

	/// finalizes all hashing threads and returns a HashMap<HashType, Vec<u8>> with the appropriate hash values.
	pub fn finalize_all(&mut self) -> HashMap<HashType, Vec<u8>> {
		let mut result = HashMap::new();
		for (hash_type, thread) in self.threads.drain() {
			result.insert(hash_type, thread.finalize());
		}
		result
	}
}


/// structure contains all information about a hashing thread.
/// This struct is used to calculate the hash of a given data in a separate thread.
/// The thread could be filled with data by using the function `fill_data`.
#[derive(Debug)]
pub(crate) struct HashingThread {
	/// triggers the hashing thread to continue the hashing process with the updated data field.
	pub trigger: crossbeam::channel::Sender<bool>,
	/// the receiver, which will be used to receive the hash of the given data.
	pub hash_receiver: crossbeam::channel::Receiver<Vec<u8>>,
}

impl HashingThread {
	/// creates a new hashing thread.
	pub fn new(hash_type: HashType, data: Arc<RwLock<Vec<u8>>>) -> Self {
		let (trigger, receiver) = crossbeam::channel::unbounded::<bool>();
		let (hash_sender, hash_receiver) = crossbeam::channel::unbounded::<Vec<u8>>();
		let c_data = Arc::clone(&data);
		let _ = thread::spawn(move || {
			let mut hasher = Hash::new_hasher(&hash_type);
			while let Ok(eof) = receiver.recv() {
				if !eof {
					let r_data = c_data.read().unwrap();
					hasher.update(&r_data);
				} else {
					let hash = hasher.finalize();
					hasher = Hash::new_hasher(&hash_type);
					hash_sender.send(hash.to_vec()).unwrap();
				}
			}
		});
		Self {
			trigger,
			hash_receiver,
		}
	}

	/// trigger the thread to continue the hashing process with the updated data field.
	pub fn trigger(&self) {
		self.trigger.send(false).unwrap();
	}

	/// returns the hash of the given data.
	/// This function blocks until the hash is calculated.
	pub fn finalize(self) -> Vec<u8> {
		self.trigger.send(true).unwrap();
		self.hash_receiver.recv().unwrap()
	}
}

/// Structure to manage the deduplication thread.
#[derive(Debug)]
pub(crate) struct DeduplicationThread {
	/// the sender, which will be used to trigger the deduplication thread.
	pub trigger: crossbeam::channel::Sender<()>,
	/// the receiver, which will be used to receive the hash of the given data.
	pub receiver: crossbeam::channel::Receiver<blake3::Hash>,
}

impl DeduplicationThread {
	/// creates a new deduplication thread.
	pub fn new(data: Arc<RwLock<Vec<u8>>>) -> Self {
		let (trigger, trigger_receiver) = crossbeam::channel::unbounded::<()>();
		let (sender, receiver) = crossbeam::channel::unbounded::<blake3::Hash>();
		let c_data = Arc::clone(&data);
		let _ = thread::spawn(move || {
			while trigger_receiver.recv().is_ok() {
				let r_data = c_data.read().unwrap();
				sender.send(blake3::hash(&r_data)).unwrap();
			}
		});
		Self {
			trigger,
			receiver,
		}
	}

	/// triggers the deduplication thread to continue the hashing process with the updated data field.
	/// This function should be called after the data field was updated.
	pub fn trigger(&self) {
		self.trigger.send(()).unwrap();
	}

	/// returns the hash of the given data.
	pub fn get_result(&self) -> blake3::Hash {
		self.receiver.recv().unwrap()
	}
}

/// Structure to manage the crc32 calculation in a separate thread.
pub(crate) struct Crc32Thread {
	/// triggers the crc32 thread to continue the crc32 calculation with the updated data field.
	pub trigger: crossbeam::channel::Sender<()>,
	/// the receiver, which will be used to receive the compressed data and if the compression flag has to be set or not.
	pub receiver: crossbeam::channel::Receiver<u32>,
}

impl Crc32Thread {
	/// creates a new crc32 thread.
	pub fn new(data: Arc<RwLock<Vec<u8>>>) -> Self {
		let (trigger, trigger_receiver) = crossbeam::channel::unbounded::<()>();
		let (sender, receiver) = crossbeam::channel::unbounded::<u32>();
		let c_data = Arc::clone(&data);
		let _ = thread::spawn(move || {
			while trigger_receiver.recv().is_ok() {
				let r_data = c_data.read().unwrap();
				let mut hasher = crc32fast::Hasher::new();
				hasher.update(&r_data);
				sender.send(hasher.finalize()).unwrap();
			}
		});
		Self {
			trigger,
			receiver,
		}
	}

	/// trigger the thread to continue the crc32 calculation with the updated data field.
	pub fn trigger(&self) {
		self.trigger.send(()).unwrap();
	}

	/// returns the crc32 of the given data.
	pub fn finalize(&self) -> u32 {
		self.receiver.recv().unwrap()
	}
}

/// Structure contains all information about a compression thread.
#[derive(Debug)]
pub(crate) struct CompressionThread {
	/// the sender, which will be used to trigger the compression thread.
	pub trigger: crossbeam::channel::Sender<()>,
	/// will be used to receive the compressed data and if the compression flag has to be set or not.
	pub result: Arc<RwLock<CompressedData>>,
}

impl CompressionThread {
	/// creates a new compression thread.
	pub fn new(compression_header: CompressionHeader, chunk_size: usize, data: Arc<RwLock<Vec<u8>>>) -> Self {
		let (trigger, trigger_receiver) = crossbeam::channel::unbounded::<()>();
		let result = Arc::new(RwLock::new(CompressedData::Raw));
		let c_result = Arc::clone(&result);
		let c_data = Arc::clone(&data);
		let _ = thread::spawn(move || {
			while trigger_receiver.recv().is_ok() {
				let r_data = c_data.read().unwrap();
				let mut w_result = c_result.write().unwrap();
				*w_result = Self::compress_buffer(&r_data, chunk_size, &compression_header);
			}
		});
		Self {
			trigger,
			result,
		}
	}

	fn compress_buffer(
		buf: &std::sync::RwLockReadGuard<'_, Vec<u8>>,
		chunk_size: usize,
		compression_header: &CompressionHeader) -> CompressedData {
		let compression_threshold = compression_header.threshold;
	
		match compression_header.algorithm {
			CompressionAlgorithm::None => CompressedData::Raw,
			CompressionAlgorithm::Zstd => {
				let compression_level = compression_header.level as i32;
				let mut stream = match zstd::stream::read::Encoder::new(buf.as_slice(), compression_level) {
					Ok(stream) => stream,
					Err(e) => return CompressedData::Err(ZffError::from(e)),
				};
				// unwrap is safe here, because the read will not fail on a Vec<u8>.
				let (compressed_data, _) = buffer_chunk(&mut stream, chunk_size * compression_header.level as usize).unwrap();
				if (buf.len() as f32 / compressed_data.len() as f32) < compression_threshold {
					CompressedData::Raw
				} else {
					CompressedData::Compressed(compressed_data)
				}
			},
			CompressionAlgorithm::Lz4 => {
				let buffer = Vec::new();
				let mut compressor = lz4_flex::frame::FrameEncoder::new(buffer);
				if let Err(e) = io_copy(&mut buf.as_slice(), &mut compressor) {
					return CompressedData::Err(ZffError::from(e));
				};
				let compressed_data = match compressor.finish() {
					Ok(data) => data,
					Err(e) => return CompressedData::Err(ZffError::from(e)),
				
				};
				if (buf.len() as f32 / compressed_data.len() as f32) < compression_threshold {
					CompressedData::Raw
				} else {
					CompressedData::Compressed(compressed_data)
				}
			}
		}
	}

	/// triggers the compression thread to continue the compression process with the updated data field.
	/// This function should be called after the data field was updated.
	pub fn trigger(&self) {
		self.trigger.send(()).unwrap();
	}

	/// returns the compressed data and if the compression flag has to be set or not.
	pub fn get_result(&self) -> RwLockReadGuard<'_, CompressedData> {
		self.result.read().unwrap()
	}
}

/// Indicates if the data are compressed or not.
/// This enum is used to avoid unnecessary copy operations.
/// If the data are compressed, the data will be used directly.
#[derive(Debug)]
pub(crate) enum CompressedData {
	/// indicates to use the compressed data (to avoid unnecessary copy operations)
	Compressed(Vec<u8>),
	/// indicates to use the original raw data (to avoid unnecessary copy operations)
	Raw,
	/// indicates an error during the compression process.
	Err(ZffError),
}

/// A structure, which contains all information and capabilities to check if the underlying data are same bytes or not.
pub(crate) struct SameBytesThread {
	/// the sender, which will be used to trigger the same bytes thread.
	pub trigger: crossbeam::channel::Sender<()>,
	/// the receiver, which will be used to receive the result of the same bytes thread.
	pub receiver: crossbeam::channel::Receiver<Option<u8>>,
}

impl SameBytesThread {
	/// creates a new same bytes thread.
	pub fn new(data: Arc<RwLock<Vec<u8>>>) -> Self {
		let (sender, receiver) = crossbeam::channel::unbounded::<Option<u8>>();
		let (trigger, trigger_receiver) = crossbeam::channel::unbounded::<()>();
		let c_data = Arc::clone(&data);
		let _ = thread::spawn(move || {
			while trigger_receiver.recv().is_ok() {
				let r_data = c_data.read().unwrap();
				let result = Self::check_same_bytes(&r_data);
				sender.send(result).unwrap();
			}
		});
		Self {
			trigger,
			receiver,
		}
	}

	/// checks if the given data are same bytes or not.
	pub fn check_same_bytes(buf: &std::sync::RwLockReadGuard<'_, Vec<u8>>) -> Option<u8> {
		if check_same_byte(buf) {
			Some(buf[0])
		} else {
			None
		}
	}

	/// triggers the same bytes thread to continue the same bytes check with the updated data field.
	/// This function should be called after the data field was updated.
	pub fn trigger(&self) {
		self.trigger.send(()).unwrap();
	}

	/// returns the result of the same bytes check.
	pub fn get_result(&self) -> Option<u8> {
		self.receiver.recv().unwrap()
	}
}

/// creates a chunk by using the given data and the given chunk size.
pub(crate) fn chunking(
	encoding_thread_pool_manager: &mut EncodingThreadPoolManager,
	current_chunk_number: u64,
	samebyte_checklen_value: u64,
	chunk_size: u64, // target chunk size,
	deduplication_map: Option<&mut DeduplicationChunkMap>,
	encryption_key: Option<&Vec<u8>>,
	encryption_algorithm: Option<&EncryptionAlgorithm>,
) -> Result<Vec<u8>> {
	let mut chunk = Vec::new();
	// create chunk header
	let mut chunk_header = ChunkHeader::new_empty(current_chunk_number);

	// check same byte
	// if the length of the buffer is not equal the target chunk size, 
	// the condition failed and same byte flag can not be set.
	let same_bytes = encoding_thread_pool_manager.same_bytes_thread.get_result();
	let chunk_content = if samebyte_checklen_value == chunk_size && same_bytes.is_some() {
		chunk_header.flags.same_bytes = true;
		#[allow(clippy::unnecessary_unwrap)] //TODO: Remove this until https://github.com/rust-lang/rust/issues/53667 is stable.
		ChunkContent::SameBytes(same_bytes.unwrap()) //unwrap should be safe here, because we have already testet this before.
	} else if let Some(deduplication_map) = deduplication_map {
		// unwrap should be safe here, because we have already testet this before.
		let b3h = encoding_thread_pool_manager.hashing_threads.get_deduplication_result();
		if let Ok(chunk_no) = deduplication_map.get_chunk_number(b3h) {
			chunk_header.flags.duplicate = true;
			ChunkContent::Duplicate(chunk_no)
		} else {
			deduplication_map.append_entry(current_chunk_number, b3h)?;
			ChunkContent::Raw(Vec::new())
		}
	} else {
		ChunkContent::Raw(Vec::new())
	};

	let (chunked_data, compression_flag) = match chunk_content {
		ChunkContent::SameBytes(single_byte) => (vec![single_byte], false),
		ChunkContent::Duplicate(chunk_no) => (chunk_no.to_le_bytes().to_vec(), false),
		ChunkContent::Raw(_) => {
			match &*encoding_thread_pool_manager.compression_thread.get_result() {
				CompressedData::Compressed(compressed_data) => (compressed_data.clone(), true),
				CompressedData::Raw => (encoding_thread_pool_manager.data.read().unwrap().clone(), false),
				CompressedData::Err(_) => return Err(ZffError::new(ZffErrorKind::Custom, "Compression error")),
			}
		},
	};

	// prepare chunk header:
	chunk_header.crc32 = encoding_thread_pool_manager.crc32_thread.finalize();
	if compression_flag {
		chunk_header.flags.compression = true;
	}
	let mut chunked_data = match &encryption_key {
		Some(encryption_key) => {
			let encryption_algorithm = match encryption_algorithm {
				Some(algorithm) => algorithm,
				None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionHeader, "")),
			};
			//TODO: check to encrypt the content if the chunked data also in the "compression_thread"?.
			Encryption::encrypt_chunk_content(
				encryption_key,
				&chunked_data,
				chunk_header.chunk_number,
				encryption_algorithm)?
		},
		None => chunked_data,
	};
	
	chunk_header.chunk_size = chunked_data.len() as u64;

	let mut encoded_header = if let Some(key) = encryption_key {
		let encryption_algorithm = match encryption_algorithm {
			Some(algorithm) => algorithm,
			None => return Err(ZffError::new(ZffErrorKind::MissingEncryptionHeader, "")),
		};
		chunk_header.encrypt_and_consume(key, encryption_algorithm)?.encode_directly()
	} else {
		chunk_header.encode_directly()
	};

	chunk.append(&mut encoded_header);
	chunk.append(&mut chunked_data);
	Ok(chunk)
}