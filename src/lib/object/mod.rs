// - STD
use std::sync::{
    Arc,
    RwLock,
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
    header::CompressionHeader,
    HashType,
    Hash,
    CompressionAlgorithm,
    io::{buffer_chunk, check_same_byte},
};

/// creates a EncodingThreadPoolManager which contains a HashingThreadManager and a CompressionThread and a Crc32Thread.
/// The EncodingThreadPoolManager is used to manage the threads and to ensure that the threads will use the given data in zero-copy way.
pub struct EncodingThreadPoolManager {
    /// the hashing threads.
    pub hashing_threads: HashingThreadManager,
    /// the compression thread.
    pub compression_thread: CompressionThread,
    /// the crc32 thread.
    pub crc32_thread: Crc32Thread,
	/// the same bytes thread.
	pub same_bytes_thread: SameBytesThread,
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

    /// triggers the underlying HashingThreadManager, the CompressionThread and the Crc32Thread to continue processes with the updated data field.
    /// This function should be called after the data field was updated.
    pub fn trigger(&mut self) {
		self.same_bytes_thread.trigger();
        self.hashing_threads.trigger();
        self.compression_thread.trigger();
        self.crc32_thread.trigger();
    }
}

/// Structure to manage the HashingThreads and ensures that the threads will use the given data in zero-copy way.
#[derive(Debug)]
pub struct HashingThreadManager {
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

	/// checks if a hashing thread with the given HashType exists.
	pub fn has_thread(&self, hash_type: &HashType) -> bool {
		self.threads.get(hash_type).is_some()
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
		for thread in self.threads.values_mut() {
			thread.trigger();
		}
		for thread in self.threads.values_mut() {
			thread.reader_created.recv().unwrap();
		}
		// trigger the deduplication thread (if exists)
		if let Some(thread) = &self.deduplication_thread {
			thread.trigger();
		}
	}

	/// finalizes the hashing thread and returns the hash of the given data and removes the thread from the HashingThreadManager.
	pub fn finalize(&mut self, hash_type: HashType) -> Option<Vec<u8>> {
		self.threads.remove(&hash_type).map(|thread| thread.finalize())
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
pub struct HashingThread {
	/// the thread, which calculates the hash of the given data.
	pub thread: thread::JoinHandle<()>,
	/// the data, which will be used by the hashing thread.
	pub data: Arc<RwLock<Vec<u8>>>,
	/// triggers the hashing thread to continue the hashing process with the updated data field.
	pub trigger: crossbeam::channel::Sender<bool>,
	/// contains a receiver, which will be used to ensure, that the thread has accessed the data field.
	pub reader_created: crossbeam::channel::Receiver<()>,
	/// the receiver, which will be used to receive the hash of the given data.
	pub hash_receiver: crossbeam::channel::Receiver<Vec<u8>>,
}

impl HashingThread {
	/// creates a new hashing thread.
	pub fn new(hash_type: HashType, data: Arc<RwLock<Vec<u8>>>) -> Self {
		let (trigger, receiver) = crossbeam::channel::unbounded::<bool>();
		let (reader_created, reader_created_receiver) = crossbeam::channel::unbounded::<()>(); // this channel will be used to ensure, that the thread has accessed the data field
		let (hash_sender, hash_receiver) = crossbeam::channel::unbounded::<Vec<u8>>();
		let c_data = Arc::clone(&data);
		let thread = thread::spawn(move || {
			let mut hasher = Hash::new_hasher(&hash_type);
			while let Ok(eof) = receiver.recv() {
				if !eof {
					let r_data = c_data.read().unwrap();
					reader_created.send(()).unwrap();
					hasher.update(&r_data);
				} else {
					let hash = hasher.finalize();
					hasher = Hash::new_hasher(&hash_type);
					hash_sender.send(hash.to_vec()).unwrap();
				}
			}
		});
		Self {
			thread,
			data,
			trigger,
			reader_created: reader_created_receiver,
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
pub struct DeduplicationThread {
	/// the thread, which will be used to calculate the hash of the given data.
	pub thread: thread::JoinHandle<()>,
	/// the data, which will be used by the deduplication thread.
	pub data: Arc<RwLock<Vec<u8>>>,
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
		let thread = thread::spawn(move || {
			while trigger_receiver.recv().is_ok() {
				let r_data = c_data.read().unwrap();
				sender.send(blake3::hash(&r_data)).unwrap();
			}
		});
		Self {
			thread,
			data,
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
pub struct Crc32Thread {
	/// the thread, which calculates the crc32 of the given data.
	pub thread: thread::JoinHandle<()>,
	/// the data, which will be used by the crc32 thread.
	pub data: Arc<RwLock<Vec<u8>>>,
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
		let thread = thread::spawn(move || {
			while trigger_receiver.recv().is_ok() {
				let r_data = c_data.read().unwrap();
				let mut hasher = crc32fast::Hasher::new();
				hasher.update(&r_data);
				sender.send(hasher.finalize()).unwrap();
			}
		});
		Self {
			thread,
			data,
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
pub struct CompressionThread {
	/// the thread, which will be used to compress the data.
	pub thread: thread::JoinHandle<()>,
	/// the data, which will be used by the compression thread.
	pub data: Arc<RwLock<Vec<u8>>>,
	/// the sender, which will be used to trigger the compression thread.
	pub trigger: crossbeam::channel::Sender<()>,
	/// the receiver, which will be used to receive the compressed data and if the compression flag has to be set or not.
	pub receiver: crossbeam::channel::Receiver<Result<(Vec<u8>, bool)>>,
}

impl CompressionThread {
	/// creates a new compression thread.
	pub fn new(compression_header: CompressionHeader, chunk_size: usize, data: Arc<RwLock<Vec<u8>>>) -> Self {
		let (sender, receiver) = crossbeam::channel::unbounded::<Result<(Vec<u8>, bool)>>();
		let (trigger, trigger_receiver) = crossbeam::channel::unbounded::<()>();
		let c_data = Arc::clone(&data);
		let thread = thread::spawn(move || {
			while trigger_receiver.recv().is_ok() {
				let r_data = c_data.read().unwrap();
				let result = Self::compress_buffer(&r_data, chunk_size, &compression_header);
				sender.send(result).unwrap();
			}
		});
		Self {
			thread,
			data,
			trigger,
			receiver,
		}
	}

	fn compress_buffer(buf: &std::sync::RwLockReadGuard<'_, Vec<u8>>, chunk_size: usize, compression_header: &CompressionHeader) -> Result<(Vec<u8>, bool)> {
		let mut compression_flag = false;
		let compression_threshold = compression_header.threshold;
	
		match compression_header.algorithm {
			CompressionAlgorithm::None => Ok((buf.to_vec(), compression_flag)),
			CompressionAlgorithm::Zstd => {
				let compression_level = compression_header.level as i32;
				let mut stream = zstd::stream::read::Encoder::new(buf.as_slice(), compression_level)?;
				// unwrap is safe here, because the read will not fail on a Vec<u8>.
				let (compressed_data, _) = buffer_chunk(&mut stream, chunk_size * compression_header.level as usize).unwrap();
				if (buf.len() as f32 / compressed_data.len() as f32) < compression_threshold {
					Ok((buf.to_vec(), compression_flag))
				} else {
					compression_flag = true;
					Ok((compressed_data, compression_flag))
				}
			},
			CompressionAlgorithm::Lz4 => {
				let buffer = Vec::new();
				let mut compressor = lz4_flex::frame::FrameEncoder::new(buffer);
				io_copy(&mut buf.as_slice(), &mut compressor)?;
				let compressed_data = compressor.finish()?;
				if (buf.len() as f32 / compressed_data.len() as f32) < compression_threshold {
					Ok((buf.to_vec(), compression_flag))
				} else {
					compression_flag = true;
					Ok((compressed_data, compression_flag))
				}
			}
		}
	}
	

	/// fills the data field of the compression thread.
	pub fn update(&self, data: Vec<u8>) {
		let mut w = self.data.write().unwrap();
		*w = data;
	}

	/// triggers the compression thread to continue the compression process with the updated data field.
	/// This function should be called after the data field was updated.
	pub fn trigger(&self) {
		self.trigger.send(()).unwrap();
	}

	/// returns the compressed data and if the compression flag has to be set or not.
	pub fn get_result(&self) -> Result<(Vec<u8>, bool)> {
		self.receiver.recv().unwrap()
	}
}

/// A structure, which contains all information and capabilities to check if the underlying data are same bytes or not.
pub struct SameBytesThread {
	/// the thread, which will be used to check if the underlying data are same bytes or not.
	pub thread: thread::JoinHandle<()>,
	/// the data, which will be used by the same bytes thread.
	pub data: Arc<RwLock<Vec<u8>>>,
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
		let thread = thread::spawn(move || {
			while trigger_receiver.recv().is_ok() {
				let r_data = c_data.read().unwrap();
				let result = Self::check_same_bytes(&r_data);
				sender.send(result).unwrap();
			}
		});
		Self {
			thread,
			data,
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