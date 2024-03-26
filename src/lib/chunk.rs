// - STD
use std::io::Read;
use std::borrow::Borrow;

// - internal
use crate::{
	header::{ChunkHeader, EncryptedChunkHeader}, HeaderCoding, Result, EncryptionAlgorithm, Encryption, CompressionAlgorithm,
};

/// This struct represents a full [Chunk], including the appriopriate [crate::header::ChunkHeader] and the chunked data (encoded; compressed and/or encrypted, if set).
pub struct Chunk {
	header: ChunkHeader,
	data: Vec<u8>
}

impl Chunk {
	/// Returns a new [Chunk] with the given values.
	pub fn new(header: ChunkHeader, data: Vec<u8>) -> Chunk {
		Self {
			header,
			data
		}
	}

	/// Returns a new [Chunk], read from the given [Reader](std::io::Read).
	pub fn new_from_reader<R: Read>(data: &mut R) -> Result<Chunk> {
		let chunk_header = ChunkHeader::decode_directly(data)?;
		let mut chunk_data = vec![0; chunk_header.chunk_size as usize];
		data.read_exact(&mut chunk_data)?;
		Ok(Self::new(chunk_header, chunk_data))
	}

	/// Returns the underlying [crate::header::ChunkHeader].
	pub fn header(&self) -> &ChunkHeader {
		&self.header
	}

	/// Returns the underlying data.
	pub fn data(&self) -> &Vec<u8> {
		&self.data
	}

	/// Checks the integrity of the chunk data by calculating the appropriate crc32 hash.
	/// Returns true if the crc32 hash is equal to the hash in the header, otherwise false.
	pub fn check_integrity<C>(&self, object_compression_algorithm: C) -> Result<bool> 
	where
		C: Borrow<CompressionAlgorithm>,
	{
		// decompress inner data if neccessary.
		let data = if self.header.flags.compression {
			crate::compression::decompress_buffer(&self.data, object_compression_algorithm.borrow())?
		} else {
			self.data.clone()
		};
		let mut hasher = crc32fast::Hasher::new();
		hasher.update(&data);
		let crc32 = hasher.finalize();
		Ok(crc32 == self.header.crc32)
	}
}

/// This struct represents a full [EncryptedChunk], including the appriopriate [crate::header::EncryptedChunkHeader] and the chunked data (encoded; compressed and/or encrypted, if set).
pub struct EncryptedChunk {
	encrypted_header: EncryptedChunkHeader,
	data: Vec<u8>
}

impl EncryptedChunk {
	/// Returns a new [EncryptedChunk] with the given values.
	pub fn new(encrypted_header: EncryptedChunkHeader, data: Vec<u8>) -> EncryptedChunk {
		Self {
			encrypted_header,
			data
		}
	}

	/// Returns a new [EncryptedChunk], read from the given [Reader](std::io::Read).
	pub fn new_from_reader<R: Read>(data: &mut R) -> Result<EncryptedChunk> {
		let encrypted_chunk_header = EncryptedChunkHeader::decode_directly(data)?;
		let mut chunk_data = vec![0; encrypted_chunk_header.chunk_size as usize];
		data.read_exact(&mut chunk_data)?;
		Ok(Self::new(encrypted_chunk_header, chunk_data))
	}

	/// Returns the underlying [crate::header::EncryptedChunkHeader].
	pub fn header(&self) -> &EncryptedChunkHeader {
		&self.encrypted_header
	}

	/// Returns the underlying data.
	pub fn data(&self) -> &Vec<u8> {
		&self.data
	}

	/// Decrypts the [EncryptedChunk] with the given key and algorithm.
	pub fn decrypt<K, A>(&self, key: K, algorithm: A) -> Result<Chunk> 
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		let header = self.encrypted_header.decrypt(&key, algorithm.borrow())?;
		// decrypt data if the appropraite encryption flag is set.
		// The header can be encrypted while the data is not - this is a case e.g. of an chunk with empty data.
		let data = if header.flags.encryption && !self.data.is_empty() {
			Encryption::decrypt_chunk_content(key, &self.data, header.chunk_number, algorithm.borrow())?
		} else {
			self.data.clone()
		};
		Ok(Chunk::new(header, data))
	}

	/// Decrypts the [EncryptedChunk] with the given key and algorithm and consumes the [EncryptedChunk].
	pub fn decrypt_and_consume<K, A>(self, key:K, algorithm: A) -> Result<Chunk>
	where
		A: Borrow<EncryptionAlgorithm>,
		K: AsRef<[u8]>,
	{
		self.decrypt(key, algorithm)
	}
}