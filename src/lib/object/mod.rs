// - STD
use std::sync::{
    Arc,
    RwLock, RwLockReadGuard,
};
use std::collections::HashMap;
use std::thread::{self};
use std::io::{copy as io_copy, Read, Seek};

// - modules
mod encoder; 

// - re-exports
pub use encoder::*;

// - internal
use crate::{
    Result,
    header::{CompressionHeader, ChunkHeader},
    HashType,
    Hash,
    CompressionAlgorithm,
	PreparedChunk,
    io::{buffer_chunk, check_same_byte, calculate_xxhash},
	header::{ChunkFlags, DeduplicationMetadata},
	error::{ZffError, ZffErrorKind},
	encryption::{Encryption, EncryptionAlgorithm},
	ChunkContent,
	constants::*,
};

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

/// The EncodingThreadPoolManager is used to manage the threads and to ensure that the threads will use the given data in zero-copy way.
/// 
/// The EncodingThreadPoolManager contains the following threads:
/// - HashingThreadManager: The HashingThreadManager is used to manage the hashing threads.
/// - CompressionThread: The CompressionThread is used to compress the data.
/// - XxHashThread: The XxHashThread is used to calculate the xxh3 64bit of the data.
/// - SameBytesThread: The SameBytesThread is used to check if the data are same bytes or not.
#[derive(Debug)]
pub struct EncodingThreadPoolManager {
    /// the hashing threads.
    hashing_threads: HashingThreadManager,
    /// the compression thread.
    compression_thread: CompressionThread,
    /// the xxhash thread.
    xxhash_thread: XxHashThread,
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
            xxhash_thread: XxHashThread::new(Arc::clone(&data)),
            data,
        }
    }

    /// adds a new hashing thread to the underlying ThreadPoolManager.
    pub fn add_hashing_thread(&mut self, hash_type: HashType) {
        self.hashing_threads.add_thread(hash_type);
    }

    /// updates the data of the hashing threads.
    pub fn update(&mut self, data: Vec<u8>) {
        {
			let mut w = self.data.write().unwrap();
			*w = data;
		}	
		self.trigger();
    }

	/// finalizes all hashing threads and returns a `HashMap<HashType, Vec<u8>>` with the appropriate hash values.
	pub fn finalize_all_hashing_threads(&mut self) -> HashMap<HashType, Vec<u8>> {
		self.hashing_threads.finalize_all()
	}

    /// triggers the underlying HashingThreadManager, the CompressionThread and the XxHashThread to continue processes with the updated data field.
    /// This function should be called after the data field was updated.
    fn trigger(&mut self) {
		self.same_bytes_thread.trigger();
        self.compression_thread.trigger();
        self.xxhash_thread.trigger();
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
		if !self.threads.contains_key(&hash_type) {
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
	pub fn get_deduplication_result(&mut self) -> RwLockReadGuard<'_, blake3::Hash> {
		if self.deduplication_thread.is_none() {
			self.add_deduplication_thread();
			self.deduplication_thread.as_mut().unwrap().trigger();
		}
		self.deduplication_thread.as_mut().unwrap().get_result()
	}

	/// triggers all hashing threads to continue the hashing process with the updated data field.
	/// This function should be called after the data field was updated.
	pub fn trigger(&mut self) {
		for thread in self.threads.values_mut() {
			let wg = crossbeam::sync::WaitGroup::new();
			thread.trigger(wg.clone());
			wg.wait();
		}
		// trigger the deduplication thread (if exists)
		if let Some(thread) = &mut self.deduplication_thread {
			thread.trigger();
		}
	}

	/// finalizes all hashing threads and returns a HashMap<HashType, Vec<u8>> with the appropriate hash values.
	pub fn finalize_all(&mut self) -> HashMap<HashType, Vec<u8>> {
		let mut result = HashMap::new();
		for (hash_type, thread) in &self.threads {
			result.insert(hash_type.clone(), thread.finalize());
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
	pub trigger: crossbeam::channel::Sender<(crossbeam::sync::WaitGroup, bool)>,
	/// the receiver, which will be used to receive the hash of the given data.
	pub hash_receiver: crossbeam::channel::Receiver<Vec<u8>>,
}

impl HashingThread {
	/// creates a new hashing thread.
	pub fn new(hash_type: HashType, data: Arc<RwLock<Vec<u8>>>) -> Self {
		let (trigger, receiver) = crossbeam::channel::unbounded::<(crossbeam::sync::WaitGroup, bool)>();
		let (hash_sender, hash_receiver) = crossbeam::channel::unbounded::<Vec<u8>>();
		let c_data = Arc::clone(&data);
		let _ = thread::spawn(move || {
			let mut hasher = Hash::new_hasher(&hash_type);
			while let Ok((wg, eof)) = receiver.recv() {
				if !eof {
					let r_data = c_data.read().unwrap();
					drop(wg);
					hasher.update(&r_data);
				} else {
					let hash = hasher.finalize_reset();
					drop(wg);
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
	pub fn trigger(&self, wg: crossbeam::sync::WaitGroup) {
		self.trigger.send((wg, false)).unwrap();
	}

	/// returns the hash of the given data.
	/// This function blocks until the hash is calculated.
	pub fn finalize(&self) -> Vec<u8> {
		let wg = crossbeam::sync::WaitGroup::new();
		self.trigger.send((wg.clone(), true)).unwrap();
		wg.wait();
		self.hash_receiver.recv().unwrap()
	}
}

/// Structure to manage the deduplication thread.
#[derive(Debug)]
pub(crate) struct DeduplicationThread {
	/// triggers the deduplication thread to continue the hashing process with the updated data field.
	pub trigger: crossbeam::channel::Sender<crossbeam::sync::WaitGroup>,
	/// will be used to receive the hash of the given data.
	pub result: Arc<RwLock<blake3::Hash>>, //TODO: Use xxhash additionally?
	/// the waitgroup, which will be used to wait until the deduplication thread has finished the hashing process.
	waitgroup: Option<crossbeam::sync::WaitGroup>,
}

impl DeduplicationThread {
	/// creates a new deduplication thread.
	pub fn new(data: Arc<RwLock<Vec<u8>>>) -> Self {
		let (trigger, trigger_receiver) = crossbeam::channel::unbounded::<crossbeam::sync::WaitGroup>();
		let result = Arc::new(RwLock::new(blake3::hash(vec![0_u8].as_slice()))); //initial value is not important.
		let c_result = Arc::clone(&result);
		let c_data = Arc::clone(&data);
		let _ = thread::spawn(move || {
			while let Ok(wg) = trigger_receiver.recv() {
				let mut w_result = c_result.write().unwrap();
				let r_data = c_data.read().unwrap();
				*w_result = blake3::hash(&r_data);
				drop(wg);
			}
		});
		Self {
			trigger,
			result,
			waitgroup: None,
		}
	}

	/// triggers the deduplication thread to continue the hashing process with the updated data field.
	/// This function should be called after the data field was updated.
	pub fn trigger(&mut self) {
		let wg = crossbeam::sync::WaitGroup::new();
		self.waitgroup = Some(wg.clone());
		self.trigger.send(wg).unwrap();
	}

	/// returns the hash of the given data.
	pub fn get_result(&mut self) -> RwLockReadGuard<'_, blake3::Hash> {
		if let Some(wg) = self.waitgroup.take() {
			wg.wait();
		}
		self.result.read().unwrap()
	}
}

/// Structure to manage the xxhash calculation in a separate thread.
#[derive(Debug)]
pub(crate) struct XxHashThread {
	/// triggers the xxhash thread to continue the xxhash calculation with the updated data field.
	pub trigger: crossbeam::channel::Sender<crossbeam::sync::WaitGroup>,
	/// will be used to receive the xxhash of the given data.
	pub result: Arc<RwLock<u64>>,
	/// the waitgroup, which will be used to wait until the xxhash thread has finished the xxhash calculation.
	waitgroup: Option<crossbeam::sync::WaitGroup>,
}

impl XxHashThread {
	/// creates a new xxhash thread.
	pub fn new(data: Arc<RwLock<Vec<u8>>>) -> Self {
		let (trigger, trigger_receiver) = crossbeam::channel::unbounded::<crossbeam::sync::WaitGroup>();
		let result = Arc::new(RwLock::new(0));
		let c_result = Arc::clone(&result);
		let c_data = Arc::clone(&data);
		let _ = thread::spawn(move || {
			while let Ok(wg) = trigger_receiver.recv() {
				let mut w_result = c_result.write().unwrap();
				let r_data = c_data.read().unwrap();
				*w_result = calculate_xxhash(&r_data);
				drop(wg);
			}
		});
		Self {
			trigger,
			result,
			waitgroup: None,
		}
	}

	/// trigger the thread to continue the xxhash calculation with the updated data field.
	pub fn trigger(&mut self) {
		let wg = crossbeam::sync::WaitGroup::new();
		self.waitgroup = Some(wg.clone());
		self.trigger.send(wg).unwrap();
	}

	/// returns the xxhash of the given data.
	pub fn get_result(&mut self) -> RwLockReadGuard<'_, u64> {
		if let Some(wg) = self.waitgroup.take() {
			wg.wait();
		}
		self.result.read().unwrap()
	}
}

/// Structure contains all information about a compression thread.
#[derive(Debug)]
pub(crate) struct CompressionThread {
	/// the sender, which will be used to trigger the compression thread.
	pub trigger: crossbeam::channel::Sender<crossbeam::sync::WaitGroup>,
	/// will be used to receive the compressed data and if the compression flag has to be set or not.
	pub result: Arc<RwLock<CompressedData>>,
	/// the waitgroup, which will be used to wait until the compression thread has finished the compression process.
	waitgroup: Option<crossbeam::sync::WaitGroup>,
}

impl CompressionThread {
	/// creates a new compression thread.
	pub fn new(compression_header: CompressionHeader, chunk_size: usize, data: Arc<RwLock<Vec<u8>>>) -> Self {
		let (trigger, trigger_receiver) = crossbeam::channel::unbounded::<crossbeam::sync::WaitGroup>();
		let result = Arc::new(RwLock::new(CompressedData::Raw));
		let c_result = Arc::clone(&result);
		let c_data = Arc::clone(&data);
		let _ = thread::spawn(move || {
			while let Ok(wg) = trigger_receiver.recv() {
				let mut w_result = c_result.write().unwrap();
				let r_data = c_data.read().unwrap();
				*w_result = Self::compress_buffer(&r_data, chunk_size, &compression_header);
				drop(wg);
			}
		});
		Self {
			trigger,
			result,
			waitgroup: None,
		}
	}

	fn compress_buffer(buf: &std::sync::RwLockReadGuard<'_, Vec<u8>>, chunk_size: usize,compression_header: &CompressionHeader) -> CompressedData {
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
				let buffered_chunk = buffer_chunk(&mut stream, chunk_size * compression_header.level as usize).unwrap();
				if (buf.len() as f32 / buffered_chunk.buffer.len() as f32) < compression_threshold {
					CompressedData::Raw
				} else {
					CompressedData::Compressed(buffered_chunk.buffer)
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
	pub fn trigger(&mut self) {
		let wg = crossbeam::sync::WaitGroup::new();
		self.waitgroup = Some(wg.clone());
		self.trigger.send(wg).unwrap();
	}

	/// returns the compressed data and if the compression flag has to be set or not.
	pub fn get_result(&mut self) -> RwLockReadGuard<'_, CompressedData> {
		if let Some(wg) = self.waitgroup.take() {
			wg.wait();
		}
		self.result.read().unwrap()
	}
}

/// A structure, which contains all information and capabilities to check if the underlying data are same bytes or not.
#[derive(Debug)]
pub(crate) struct SameBytesThread {
	/// the sender, which will be used to trigger the same bytes thread.
	pub trigger: crossbeam::channel::Sender<crossbeam::sync::WaitGroup>,
	/// the receiver, which will be used to receive the result of the same bytes thread.
	pub result: Arc<RwLock<bool>>,
	/// the waitgroup, which will be used to wait until the same bytes thread has finished the same bytes check.
	waitgroup: Option<crossbeam::sync::WaitGroup>,
}

impl SameBytesThread {
	/// creates a new same bytes thread.
	pub fn new(data: Arc<RwLock<Vec<u8>>>) -> Self {
		let (trigger, trigger_receiver) = crossbeam::channel::unbounded::<crossbeam::sync::WaitGroup>();
		let result = Arc::new(RwLock::new(false));
		let c_result = Arc::clone(&result);
		let c_data = Arc::clone(&data);
		let _ = thread::spawn(move || {
			while let Ok(wg) = trigger_receiver.recv() {
				let mut w_result = c_result.write().unwrap();
				let r_data = c_data.read().unwrap();
				*w_result = Self::check_same_bytes(&r_data);
				drop(wg)
			}
		});
		Self {
			trigger,
			result,
			waitgroup: None
		}
	}

	/// checks if the given data are same bytes or not.
	pub fn check_same_bytes(buf: &std::sync::RwLockReadGuard<'_, Vec<u8>>) -> bool {
		check_same_byte(buf)
	}

	/// triggers the same bytes thread to continue the same bytes check with the updated data field.
	/// This function should be called after the data field was updated.
	pub fn trigger(&mut self) {
		let wg = crossbeam::sync::WaitGroup::new();
		self.waitgroup = Some(wg.clone());
		self.trigger.send(wg).unwrap();
	}

	/// returns the result of the same bytes check.
	pub fn get_result(&mut self) -> RwLockReadGuard<'_, bool> {
		if let Some(wg) = self.waitgroup.take() {
			wg.wait();
		}
		self.result.read().unwrap()
	}
}

/// creates a chunk by using the given data and the given chunk size.
pub(crate) fn chunking<R: Read + Seek>(
	encoding_thread_pool_manager: &mut EncodingThreadPoolManager,
	current_chunk_number: u64,
	samebyte_checklen_value: u64,
	chunk_size: u64, // target chunk size,
	deduplication_metadata: Option<&mut DeduplicationMetadata<R>>,
	encryption_key: Option<&Vec<u8>>,
	encryption_algorithm: Option<&EncryptionAlgorithm>,
) -> Result<PreparedChunk> {
	let mut flags = ChunkFlags::default();

	let mut sambebyte = None;
	let mut duplicate = None;

	// get xxhash 
	let xxhash = *encoding_thread_pool_manager.xxhash_thread.get_result();

	// check same byte
	// if the length of the buffer is not equal the target chunk size, 
	// the condition failed and same byte flag can not be set.
	let chunk_content = if samebyte_checklen_value == chunk_size && *encoding_thread_pool_manager.same_bytes_thread.get_result() {
		flags.same_bytes = true;
		let first_byte = encoding_thread_pool_manager.data.read().unwrap()[0];
		ChunkContent::SameBytes(first_byte)
	} else if let Some(deduplication_metadata) = deduplication_metadata {
		// unwrap should be safe here, because we have already testet this before.
		let b3h = encoding_thread_pool_manager.hashing_threads.get_deduplication_result();
		if let Ok(chunk_no_set) = deduplication_metadata.deduplication_map.get_chunk_number(xxhash) {
			let mut content = None;
			for chunk_no in chunk_no_set {
				let verification_hash = match deduplication_metadata.deduplication_map.get_verification_hash(chunk_no)? {
					Some(vhash) => vhash,
					None => {
						let zffreader = match &mut deduplication_metadata.original_zffreader {
							Some(zr) => zr,
							None => break,
						};
						let chunk_data = zffreader.chunk_data(chunk_no)?;
						let verification_hash = blake3::hash(&chunk_data);
						deduplication_metadata.deduplication_map.append_verification_hash(chunk_no, verification_hash)?;
						verification_hash
					}
				};
				if verification_hash == *b3h {
					flags.duplicate = true;
					content = Some(chunk_no);
					break;
				}
			}
			match content {
				Some(chunk_no) => ChunkContent::Duplicate(chunk_no),
				None => ChunkContent::Raw(Vec::new()),
			}
		} else {
			deduplication_metadata.deduplication_map.append_entry(xxhash, current_chunk_number)?;
			ChunkContent::Raw(Vec::new())
		}
	} else {
		ChunkContent::Raw(Vec::new())
	};

	match chunk_content {
		ChunkContent::SameBytes(samebyte) => sambebyte = Some(samebyte),
		ChunkContent::Duplicate(chunk_no) => duplicate = Some(chunk_no),
		_ => (),
	}

	let (chunked_data, compression_flag) = match chunk_content {
		ChunkContent::SameBytes(single_byte) => (vec![single_byte], false),
		ChunkContent::Duplicate(chunk_no) => (chunk_no.to_le_bytes().to_vec(), false),
		ChunkContent::Raw(_) => {
			match &*encoding_thread_pool_manager.compression_thread.get_result() {
				CompressedData::Compressed(compressed_data) => (compressed_data.clone(), true),
				CompressedData::Raw => (encoding_thread_pool_manager.data.read().unwrap().clone(), false),
				CompressedData::Err(e) => return Err(ZffError::from(e)),
			}
		},
	};

	if compression_flag {
		flags.compression = true;
	}
	let chunked_data = match &encryption_key {
		Some(encryption_key) => {
			let encryption_algorithm = match encryption_algorithm {
				Some(algorithm) => algorithm,
				None => return Err(ZffError::new(ZffErrorKind::EncryptionError, ERROR_MISSING_ENCRYPTION_HEADER_KEY)),
			};
			//TODO: check to encrypt the content if the chunked data also in the "compression_thread"?.
			Vec::<u8>::encrypt(
				encryption_key,
				&chunked_data,
				current_chunk_number,
				encryption_algorithm)?
		},
		None => chunked_data,
	};
	
	let size = chunked_data.len() as u64;

	let chunk_header = ChunkHeader::new(
		0, // offset is set later
		size,
		flags,
		xxhash,
	);

	Ok(PreparedChunk::new(
		chunked_data, 
		chunk_header,
		sambebyte,
		duplicate,
	))
}