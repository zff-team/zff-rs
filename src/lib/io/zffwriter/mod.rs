// - STD
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::ops::{Add, AddAssign};

// Parent
use super::*;

// - internal
use crate::{
    footer::SegmentFooter, header::{ChunkMapType, ChunkMaps, SegmentHeader, ChunkMap},
    Segment,
    HeaderCoding,
    ValueDecoder,
    file_extension_next_value,
};

#[derive(Debug, Clone, Default)]
enum ReadBytes {
    Read(u64),
    #[default]
    NotRead,
    Finished,
}

#[derive(Debug, Clone, Default)]
enum ReadState {
    #[default]
    SegmentHeader,
    ObjectHeader,
    Chunking,
    ChunkOffsetMap,
    ChunkSizeMap,
    ChunkFlagsMap,
    ChunkXxHashMap,
    ChunkSamebytesMap,
    ChunkDeduplicationMap,
    LastChunkOffsetMapOfObject,
    LastChunkSizeMapOfObject,
    LastChunkFlagsMapOfObject,
    LastChunkXxHashMapOfObject,
    LastChunkSamebytesMapOfObject,
    LastChunkDeduplicationMapOfObject,
    ObjectFooter,
    SegmentFooter,
    MainFooter,
}

#[derive(Debug, Clone, Default)]
enum PreparedDataQueueState {
    Flags,
	Size,
	XxHash,
    SameBytes,
    Deduplication,
	Data,
    #[default]
	None,
}

#[derive(Debug, Clone)]
enum SegmentationState {
    Full(u64), // current segment number | The current segment is full
    Partial(u64), // current segment number | The current segment is not full yet
    Finished(u64), // current segment number  | The current segment is finished (you should switch to the next segment)
    FullLastSegment(u64), // the last segment is full
    FinishedLastSegment(u64), // the last segment is finished
}

impl Default for SegmentationState {
    fn default() -> Self {
        SegmentationState::Partial(INITIAL_SEGMENT_NUMBER)
    }
}

// - external
#[cfg(feature = "log")]
use log::trace;

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd)]
struct BytesRead {
    pub total: u64, // the number of bytes read from this streamer,
    pub current_segment: u64 // the number of bytes read from the current segment,
}

impl BytesRead {
    fn clean(&mut self) {
        self.current_segment = 0;
    }
}

impl Add<u64> for BytesRead {
     type Output = Self;
      
      fn add(self, other: u64) -> Self {
          Self {
              total: self.total + other,
              current_segment: self.current_segment + other
          }
      }
}

impl AddAssign<u64> for BytesRead {
     fn add_assign(&mut self, other: u64) {
         self.total += other;
         self.current_segment += other;
     }
}

#[derive(Debug, Clone, Default)]
struct ZffWriterInProgressData {
    bytes_read: BytesRead,
    encoded_segment_header: Vec<u8>, // the encoded segment header,
    encoded_segment_header_read_bytes: ReadBytes, // the number of bytes read from the encoded segment header,
    segment_footer: SegmentFooter, // the segment footer,
    current_encoded_segment_footer: Vec<u8>, // the current encoded segment footer,
    current_encoded_segment_footer_read_bytes: ReadBytes, // the number of bytes read from the current encoded segment footer,
    current_encoded_object_header: Vec<u8>, // the encoded object header of the current object,
    current_encoded_object_header_read_bytes: ReadBytes, // the number of bytes read from the encoded object header of the current object,
    chunkmaps: ChunkMaps, // The current chunkmaps,
    current_encoded_chunk_offset_map: Vec<u8>, // the current encoded chunk offset map,
    current_encoded_chunk_offset_map_read_bytes: ReadBytes, // the number of bytes read from the current encoded chunk offset map,
    current_encoded_chunk_size_map: Vec<u8>, // the current encoded chunk size map,
    current_encoded_chunk_size_map_read_bytes: ReadBytes, // the number of bytes read from the current encoded chunk size map,
    current_encoded_chunk_flags_map: Vec<u8>, // the current encoded chunk flags map,
    current_encoded_chunk_flags_map_read_bytes: ReadBytes, // the number of bytes read from the current encoded chunk flags map,
    current_encoded_chunk_xxhash_map: Vec<u8>, // the current encoded chunk xxhash map,
    current_encoded_chunk_xxhash_map_read_bytes: ReadBytes, // the number of bytes read from the current encoded chunk xxhash map,
    current_encoded_chunk_samebytes_map: Vec<u8>, // the current encoded chunk samebytes map,
    current_encoded_chunk_samebytes_map_read_bytes: ReadBytes, // the number of bytes read from the current encoded chunk samebytes map,
    current_encoded_chunk_deduplication_map: Vec<u8>, // the current encoded chunk deduplication map,
    current_encoded_chunk_deduplication_map_read_bytes: ReadBytes, // the number of bytes read from the current encoded chunk deduplication map,
    current_prepared_data_queue: Option<PreparedData>, // the current prepared data in queue,
    current_prepared_data_queue_state: PreparedDataQueueState, // the current state of the prepared data queue,
    current_encoded_chunked_data: Vec<u8>, // the current encoded chunked data,
    current_encoded_chunked_data_read_bytes: ReadBytes, // the number of bytes read from the current encoded chunked data,
    current_encoded_object_footer: Vec<u8>, // the current encoded object footer,
    current_encoded_object_footer_read_bytes: ReadBytes, // the number of bytes read from the current encoded object footer,
    main_footer: MainFooter, // the main footer,
    encoded_main_footer: Vec<u8>, // the encoded main footer,
    encoded_main_footer_read_bytes: ReadBytes, // the number of bytes read from the encoded main footer,
}

impl ZffWriterInProgressData {
    fn new() -> Self {
        Self {
            current_encoded_chunk_offset_map_read_bytes: ReadBytes::Finished,
            current_encoded_chunk_size_map_read_bytes: ReadBytes::Finished,
            current_encoded_chunk_flags_map_read_bytes: ReadBytes::Finished,
            current_encoded_chunk_xxhash_map_read_bytes: ReadBytes::Finished,
            ..Default::default()
        }
    }
}

/// Defines the output for a [ZffWriter].
/// This enum determine, that the [ZffWriter] will extend or build a new Zff container.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub enum ZffFilesOutput {
    #[default]
    /// To stream the data via implemented Read.
    Stream,
	/// Build a new container by using the appropriate Path-prefix
	/// (e.g. if "/home/user/zff_container" is given, "/home/user/zff_container.z??" will be used).
	NewContainer(PathBuf),
	/// Determine an extension of the given zff container (path).
	ExtendContainer(Vec<PathBuf>),
}


/// ZffWriter is a struct that is used to create a new zff container while using the appropriate Read implementation of this struct.
/// 
/// ZffWriter only supports to create a new zff container in a single segment.
/// For creating a multi-segment zff container, or extending an existing one, use the ZffWriter struct.
pub struct ZffWriter<R: Read> {
    object_encoder: Vec<ObjectEncoder<R>>,
	current_object_encoder: ObjectEncoder<R>, //the current object encoder
    /// The field target_segment_size will be ignored.
    optional_parameters: ZffCreationParameters,
    in_progress_data: ZffWriterInProgressData,
    read_state: ReadState,
    segmentation_state: SegmentationState,
    output: ZffFilesOutput,
}

impl<R: Read> ZffWriter<R> {
    /// Returns a new ZffWriter with the given values.
    pub fn with_data(
        physical_objects: HashMap<ObjectHeader, R>, // <ObjectHeader, input_data stream>
		logical_objects: HashMap<ObjectHeader, Vec<PathBuf>>, //<ObjectHeader, input_files>
		hash_types: Vec<HashType>,
        params: ZffCreationParameters,
        output: ZffFilesOutput,
    ) -> Result<Self> {
        setup_container(physical_objects, logical_objects, hash_types, params, output)
    }

    /// Returns the current chunk number.
    pub fn current_chunk_number(&self) -> u64 {
        self.current_object_encoder.current_chunk_number()
    }

    /// Returns the number of left files of the inner logical object (if the given object number refers to a logical object).
    pub fn files_left(&self, object_number: u64) -> Option<u64> {
        if self.current_object_encoder.obj_number() == object_number {
            return self.current_object_encoder.files_left();
        }
        for obj_encoder in &self.object_encoder {
            if obj_encoder.obj_number() == object_number {
                return obj_encoder.files_left();
            }
        }
        None
    }

    /// Returns the number of left files of the current object encoder.
    pub fn files_left_current(&self) -> Option<u64> {
        self.current_object_encoder.files_left()
    }

    /// Returns the number of left files of all inner logical objects.
    pub fn files_left_total(&self) -> u64 {
        let mut total_files = self.current_object_encoder.files_left().unwrap_or(0);
        for obj_encoder in &self.object_encoder {
            total_files += obj_encoder.files_left().unwrap_or(0);
        }
        total_files
    }

    /// Returns a reference to the outputfile of the encoder.
    pub fn output_path(&self) -> Option<PathBuf> {
        match &self.output {
            ZffFilesOutput::Stream => None,
            ZffFilesOutput::NewContainer(ref path) => Some(path.clone()),
            ZffFilesOutput::ExtendContainer(ref path_vec) => Some(path_vec[0].clone()),
        }
    }

    /// sets the next segment.
    pub fn next_segment(&mut self) -> Result<()> {
        // check if the current segment is already finished
        match self.segmentation_state {
            SegmentationState::Partial(_) => return Err(ZffError::new(ZffErrorKind::SegmentNotFinished, "")),
            SegmentationState::Full(_) => return Err(ZffError::new(ZffErrorKind::SegmentNotFinished, "")),
            SegmentationState::Finished(segment_number) => {
                    self.segmentation_state = SegmentationState::Partial(segment_number+1);
                    self.read_state = ReadState::SegmentHeader;
                    self.in_progress_data.encoded_segment_header_read_bytes = ReadBytes::NotRead;
                    self.in_progress_data.encoded_segment_header = SegmentHeader::new(
                        self.optional_parameters.unique_identifier, 
                        segment_number+1, 
                        self.optional_parameters.chunkmap_size.unwrap_or(DEFAULT_CHUNKMAP_SIZE)
                    ).encode_directly();
                    self.in_progress_data.segment_footer = SegmentFooter::default();
                    self.in_progress_data.segment_footer.first_chunk_number = self.current_object_encoder.current_chunk_number();
                    self.in_progress_data.bytes_read.clean();
                },
            SegmentationState::FullLastSegment(_) => return Err(ZffError::new(ZffErrorKind::SegmentNotFinished, "")),
            SegmentationState::FinishedLastSegment(_) => return Err(ZffError::new(ZffErrorKind::NoObjectsLeft, "")),
        }
        Ok(())
    }

    /// Generates the files for the current state of the ZFF container.
    pub fn generate_files(&mut self) -> Result<()> {
        let mut file_extension = String::from(FILE_EXTENSION_INITIALIZER);
        let mut initial_extend =  match &self.output {
            ZffFilesOutput::Stream => return Err(ZffError::new(ZffErrorKind::InvalidOption, "")), //TODO: Define other kind of error here
            ZffFilesOutput::NewContainer(_) => false,
            ZffFilesOutput::ExtendContainer(_) => true,
        };

        loop {
            file_extension = file_extension_next_value(&file_extension)?;
            let mut segment_filename = match &self.output {
                ZffFilesOutput::Stream => unreachable!(),
                ZffFilesOutput::NewContainer(ref path) => path.clone(),
                ZffFilesOutput::ExtendContainer(ref path_vec) => path_vec[0].clone(), // should never get out of bound when fn setup_container was used before.
            };

	    	let mut output_file = match initial_extend {
                false => {
                    segment_filename.set_extension(&file_extension);
                    File::create(&segment_filename)?
                },
                true => {
                    // this is only necessary to extend the existing file.
                    initial_extend = false;           
                    // Prepare the appropriate file to write to.
                    let mut file = OpenOptions::new().append(true).read(true).open(segment_filename)?;
                    file.seek(SeekFrom::End(0))?;
                    file
                },
            };

            let mut buffer = vec![0u8; DEFAULT_BUFFER_SIZE as usize];
            
            loop {
                match self.read(&mut buffer) {
                    Ok(0) => {
                        break;
                    },
                    Ok(n) => {
                        output_file.write_all(&buffer[..n])?
                    },
                    Err(e) => return Err(e.into()),
                }
            }

            match self.next_segment() {
                Ok(_) => {},
                Err(e) => match e.get_kind() {
                    ZffErrorKind::NoObjectsLeft => return Ok(()),
                     _ => return Err(e),
                }
            }
        }
    }

    /// Returns true if the chunkmap was full and flushed.
    fn check_chunkmap_is_full_and_flush(&mut self, chunk_map_type: ChunkMapType) -> Result<bool> {
        match chunk_map_type {
            ChunkMapType::OffsetMap => {
                if self.in_progress_data.chunkmaps.offset_map.is_full() {
                    self.flush_chunkmap(chunk_map_type)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            ChunkMapType::SizeMap => {
                if self.in_progress_data.chunkmaps.size_map.is_full() {
                    self.flush_chunkmap(chunk_map_type)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            ChunkMapType::FlagsMap => {
                if self.in_progress_data.chunkmaps.flags_map.is_full() {
                    self.flush_chunkmap(chunk_map_type)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            ChunkMapType::XxHashMap => {
                if self.in_progress_data.chunkmaps.xxhash_map.is_full() {
                    self.flush_chunkmap(chunk_map_type)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            ChunkMapType::SamebytesMap => {
                if self.in_progress_data.chunkmaps.same_bytes_map.is_full() {
                    self.flush_chunkmap(chunk_map_type)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            ChunkMapType::DeduplicationMap => {
                if self.in_progress_data.chunkmaps.duplicate_chunks.is_full() {
                    self.flush_chunkmap(chunk_map_type)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
        }
    }

    /// checks if the appropriate object has an encryption header and encrypts the chunkmap if necessary.
    fn encode_chunkmap<C>(&self, chunkmap: &C, last_chunk_no: u64) -> Result<Vec<u8>> 
    where
        C: ChunkMap + HeaderCoding,
    {
        if let Some(encryption_header) = &self.current_object_encoder.get_obj_header().encryption_header {
            let key = encryption_header.get_encryption_key_ref().unwrap(); //unwrap should be safe here - I don't know how we would encrypt all the other stuff, without knowing the key. :D
            let algorithm = &encryption_header.algorithm;
            Ok(chunkmap.encrypt_encoded_map(key, algorithm, last_chunk_no)?)
        } else {
             Ok(chunkmap.encode_directly())
        }
    }

    /// flushes the current chunkmap.
    fn flush_chunkmap(&mut self, chunk_map_type: ChunkMapType) -> Result<()> {

        let segment_number = self.current_segment_no();

        #[cfg(feature = "log")]
        trace!("Flush chunkmap {chunk_map_type} in segment {segment_number} at offset {}", self.in_progress_data.bytes_read.current_segment);

        match chunk_map_type {
            ChunkMapType::OffsetMap => {
                if let Some(chunk_no) = self.in_progress_data.chunkmaps.offset_map.chunkmap().keys().max() {
                    self.in_progress_data.main_footer.chunk_offset_maps.insert(*chunk_no, segment_number);
                    self.in_progress_data.segment_footer.chunk_offset_map_table.insert(*chunk_no, self.in_progress_data.bytes_read.current_segment);
                    self.in_progress_data.current_encoded_chunk_offset_map = self.encode_chunkmap(
                        &self.in_progress_data.chunkmaps.offset_map, *chunk_no)?;
                    self.in_progress_data.current_encoded_chunk_offset_map_read_bytes = ReadBytes::NotRead;
                    self.in_progress_data.chunkmaps.offset_map.flush();
                }
            },
            ChunkMapType::SizeMap => {
                if let Some(chunk_no) = self.in_progress_data.chunkmaps.size_map.chunkmap().keys().max() {
                    self.in_progress_data.main_footer.chunk_size_maps.insert(*chunk_no, segment_number);
                    self.in_progress_data.segment_footer.chunk_size_map_table.insert(*chunk_no, self.in_progress_data.bytes_read.current_segment);
                    self.in_progress_data.current_encoded_chunk_size_map = self.encode_chunkmap(
                        &self.in_progress_data.chunkmaps.size_map, *chunk_no)?;
                    self.in_progress_data.current_encoded_chunk_size_map_read_bytes = ReadBytes::NotRead;
                    self.in_progress_data.chunkmaps.size_map.flush();
                }
            },
            ChunkMapType::FlagsMap => {
                if let Some(chunk_no) = self.in_progress_data.chunkmaps.flags_map.chunkmap().keys().max() {
                    self.in_progress_data.main_footer.chunk_flags_maps.insert(*chunk_no, segment_number);
                    self.in_progress_data.segment_footer.chunk_flags_map_table.insert(*chunk_no, self.in_progress_data.bytes_read.current_segment);
                    self.in_progress_data.current_encoded_chunk_flags_map = self.encode_chunkmap(
                        &self.in_progress_data.chunkmaps.flags_map, *chunk_no)?;
                    self.in_progress_data.current_encoded_chunk_flags_map_read_bytes = ReadBytes::NotRead;
                    self.in_progress_data.chunkmaps.flags_map.flush();
                }
            },
            ChunkMapType::XxHashMap => {
                if let Some(chunk_no) = self.in_progress_data.chunkmaps.xxhash_map.chunkmap().keys().max() {
                    self.in_progress_data.main_footer.chunk_xxhash_maps.insert(*chunk_no, segment_number);
                    self.in_progress_data.segment_footer.chunk_xxhash_map_table.insert(*chunk_no, self.in_progress_data.bytes_read.current_segment);
                    self.in_progress_data.current_encoded_chunk_xxhash_map = self.encode_chunkmap(
                        &self.in_progress_data.chunkmaps.xxhash_map, *chunk_no)?;
                    self.in_progress_data.current_encoded_chunk_xxhash_map_read_bytes = ReadBytes::NotRead;
                    self.in_progress_data.chunkmaps.xxhash_map.flush();
                }
            },
            ChunkMapType::SamebytesMap => {
                if let Some(chunk_no) = self.in_progress_data.chunkmaps.same_bytes_map.chunkmap().keys().max() {
                    self.in_progress_data.main_footer.chunk_samebytes_maps.insert(*chunk_no, segment_number);
                    self.in_progress_data.segment_footer.chunk_samebytes_map_table.insert(*chunk_no, self.in_progress_data.bytes_read.current_segment);
                    self.in_progress_data.current_encoded_chunk_samebytes_map = self.encode_chunkmap(
                        &self.in_progress_data.chunkmaps.same_bytes_map, *chunk_no)?;
                    self.in_progress_data.current_encoded_chunk_samebytes_map_read_bytes = ReadBytes::NotRead;
                    self.in_progress_data.chunkmaps.same_bytes_map.flush();
                }
            },
            ChunkMapType::DeduplicationMap => {
                if let Some(chunk_no) = self.in_progress_data.chunkmaps.duplicate_chunks.chunkmap().keys().max() {
                    self.in_progress_data.main_footer.chunk_dedup_maps.insert(*chunk_no, segment_number);
                    self.in_progress_data.segment_footer.chunk_dedup_map_table.insert(*chunk_no, self.in_progress_data.bytes_read.current_segment);
                    self.in_progress_data.current_encoded_chunk_deduplication_map = self.encode_chunkmap(
                        &self.in_progress_data.chunkmaps.duplicate_chunks, *chunk_no)?;
                    self.in_progress_data.current_encoded_chunk_deduplication_map_read_bytes = ReadBytes::NotRead;
                    self.in_progress_data.chunkmaps.duplicate_chunks.flush();
                }
            },
        }
        Ok(())
    }

    fn current_segment_no(&self) -> u64 {
        match self.segmentation_state {
            SegmentationState::Partial(segment_number) => segment_number,
            SegmentationState::Full(segment_number) => segment_number,
            SegmentationState::Finished(segment_number) => segment_number,
            SegmentationState::FullLastSegment(segment_number) => segment_number,
            SegmentationState::FinishedLastSegment(segment_number) => segment_number,
        }
    }

}

impl<R: Read> Read for ZffWriter<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut bytes_written_to_buffer = 0; // the number of bytes which are written to the current buffer,

        // may improve performance in different cases.
        let buf_len = buf.len();

        'read_loop: loop {
            match self.segmentation_state {
                SegmentationState::Finished(_) => {
                    return Ok(bytes_written_to_buffer);
                },
                SegmentationState::FinishedLastSegment(_) => {
                    return Ok(bytes_written_to_buffer);
                },
                _ => {},
            }

            match self.read_state {
                ReadState::SegmentHeader => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::SegmentHeader");
                    // reads the segment header if not already read
                    // this is the initial state.
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.encoded_segment_header, 
                        &mut self.in_progress_data.encoded_segment_header_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };
                    
                    // switch to the next state
                    match self.in_progress_data.current_encoded_object_header_read_bytes {
                        ReadBytes::Finished => {
                            self.read_state = ReadState::Chunking;
                        },
                        _ => {
                            self.read_state = ReadState::ObjectHeader;
                            self.in_progress_data.main_footer.object_header.insert(
                                self.current_object_encoder.obj_number(), self.current_segment_no());
                            // prepare the current object header
                            self.in_progress_data.current_encoded_object_header = self.current_object_encoder.get_encoded_header();
                            self.in_progress_data.segment_footer.add_object_header_offset(
                                self.current_object_encoder.obj_number(),
                                self.in_progress_data.bytes_read.current_segment);
                        },
                    }
                },
                ReadState::ObjectHeader => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::ObjectHeader");
                    // reads the current object header if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_object_header, 
                        &mut self.in_progress_data.current_encoded_object_header_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };

                    // switch to the next state
                    self.read_state = ReadState::ChunkOffsetMap;
                },
                ReadState::ChunkOffsetMap => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::ChunkOffsetMap");
                    // reads the chunkmap if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_chunk_offset_map, 
                        &mut self.in_progress_data.current_encoded_chunk_offset_map_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };

                    // switch to the next state
                    match self.segmentation_state {
                        SegmentationState::Partial(_) => self.read_state = ReadState::Chunking,
                        SegmentationState::Full(_) => {
                            self.read_state = ReadState::ChunkSizeMap;
                            self.flush_chunkmap(ChunkMapType::SizeMap)?;
                        },
                        SegmentationState::Finished(_) => unreachable!(),
                        SegmentationState::FullLastSegment(_) => unreachable!(),
                        SegmentationState::FinishedLastSegment(_) => unreachable!(),
                    };
                },

                ReadState::ChunkSizeMap => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::ChunkSizeMap");
                    // reads the chunkmap if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_chunk_size_map, 
                        &mut self.in_progress_data.current_encoded_chunk_size_map_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };

                    // switch to the next state
                    match self.segmentation_state {
                        SegmentationState::Partial(_) => self.read_state = ReadState::Chunking,
                        SegmentationState::Full(_) => {
                            self.read_state = ReadState::ChunkFlagsMap;
                            self.flush_chunkmap(ChunkMapType::FlagsMap)?;
                        },
                        SegmentationState::Finished(_) => unreachable!(),
                        SegmentationState::FullLastSegment(_) => unreachable!(),
                        SegmentationState::FinishedLastSegment(_) => unreachable!(),
                    };
                },

                ReadState::ChunkFlagsMap => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::ChunkFlagsMap");
                    // reads the chunkmap if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_chunk_flags_map, 
                        &mut self.in_progress_data.current_encoded_chunk_flags_map_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };

                    // switch to the next state
                    match self.segmentation_state {
                        SegmentationState::Partial(_) => self.read_state = ReadState::Chunking,
                        SegmentationState::Full(_) => {
                            self.read_state = ReadState::ChunkXxHashMap;
                            self.flush_chunkmap(ChunkMapType::XxHashMap)?;
                        },
                        SegmentationState::Finished(_) => unreachable!(),
                        SegmentationState::FullLastSegment(_) => unreachable!(),
                        SegmentationState::FinishedLastSegment(_) => unreachable!(),
                    };
                },

                ReadState::ChunkXxHashMap => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::ChunkXxHashMap");
                    // reads the chunkmap if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_chunk_xxhash_map, 
                        &mut self.in_progress_data.current_encoded_chunk_xxhash_map_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };

                    // switch to the next state
                    match self.segmentation_state {
                        SegmentationState::Partial(_) => self.read_state = ReadState::Chunking,
                        SegmentationState::Full(_) => {
                            self.read_state = ReadState::ChunkSamebytesMap;
                            self.flush_chunkmap(ChunkMapType::SamebytesMap)?;
                        },
                        SegmentationState::Finished(_) => unreachable!(),
                        SegmentationState::FullLastSegment(_) => unreachable!(),
                        SegmentationState::FinishedLastSegment(_) => unreachable!(),
                    };
                },

                ReadState::ChunkSamebytesMap => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::ChunkSamebytesMap");
                    // reads the chunkmap if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_chunk_samebytes_map, 
                        &mut self.in_progress_data.current_encoded_chunk_samebytes_map_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };
                    // switch to the next state
                    match self.segmentation_state {
                        SegmentationState::Partial(_) => self.read_state = ReadState::Chunking,
                        SegmentationState::Full(_) => {
                            self.read_state = ReadState::ChunkDeduplicationMap;
                            self.flush_chunkmap(ChunkMapType::DeduplicationMap)?;
                        },
                        SegmentationState::Finished(_) => unreachable!(),
                        SegmentationState::FullLastSegment(_) => unreachable!(),
                        SegmentationState::FinishedLastSegment(_) => unreachable!(),
                    };
                },

                ReadState::ChunkDeduplicationMap => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::ChunkDeduplicationMap");
                    // reads the chunkmap if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_chunk_deduplication_map, 
                        &mut self.in_progress_data.current_encoded_chunk_deduplication_map_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };

                    // switch to the next state
                    match self.segmentation_state {
                        SegmentationState::Partial(_) => self.read_state = ReadState::Chunking,
                        SegmentationState::Full(_) => self.read_state = ReadState::SegmentFooter,
                        SegmentationState::Finished(_) => unreachable!(),
                        SegmentationState::FullLastSegment(_) => unreachable!(),
                        SegmentationState::FinishedLastSegment(_) => unreachable!(),
                    };

                    match self.read_state {
                        ReadState::SegmentFooter => {
                            self.in_progress_data.segment_footer.set_footer_offset(self.in_progress_data.bytes_read.current_segment);
                            self.in_progress_data.segment_footer.set_length_of_segment(
                                self.in_progress_data.bytes_read.current_segment + 
                                self.in_progress_data.segment_footer.encode_directly().len() as u64);
                            self.in_progress_data.current_encoded_segment_footer = self.in_progress_data.segment_footer.encode_directly();
                            self.in_progress_data.current_encoded_segment_footer_read_bytes = ReadBytes::NotRead;
                        },
                        _ => (),
                    };
                },

                ReadState::LastChunkOffsetMapOfObject => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::LastChunkOffsetMapOfObject");
                    // reads the chunkmap if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_chunk_offset_map, 
                        &mut self.in_progress_data.current_encoded_chunk_offset_map_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };
                    
                    // prepare and switch to the next state
                    // write the chunk size map even there is some space left in map to ensure
                    // that this map will be written if there is no next object.
                    self.flush_chunkmap(ChunkMapType::SizeMap)?;
                    self.read_state = ReadState::LastChunkSizeMapOfObject;
                },

                ReadState::LastChunkSizeMapOfObject => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::LastChunkSizeMapOfObject");
                    // reads the chunkmap if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_chunk_size_map, 
                        &mut self.in_progress_data.current_encoded_chunk_size_map_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };

                    // prepare and switch to the next state
                    // write the chunk flags map even there is some space left in map to ensure
                    // that this map will be written if there is no next object.
                    self.flush_chunkmap(ChunkMapType::FlagsMap)?;
                    self.read_state = ReadState::LastChunkFlagsMapOfObject;
                },

                ReadState::LastChunkFlagsMapOfObject => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::LastChunkFlagsMapOfObject");
                    // reads the chunkmap if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_chunk_flags_map, 
                        &mut self.in_progress_data.current_encoded_chunk_flags_map_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };

                    // prepare and switch to the next state
                    // write the chunk xxhash map even there is some space left in map to ensure
                    // that this map will be written if there is no next object.
                    self.flush_chunkmap(ChunkMapType::XxHashMap)?;
                    self.read_state = ReadState::LastChunkXxHashMapOfObject;
                },

                ReadState::LastChunkXxHashMapOfObject => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::LastChunkXxHashMapOfObject");
                    // reads the chunkmap if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_chunk_xxhash_map, 
                        &mut self.in_progress_data.current_encoded_chunk_xxhash_map_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };

                    // prepare and switch to the next state
                    // write the chunk samebytes map even there is some space left in map to ensure
                    // that this map will be written if there is no next object.
                    self.flush_chunkmap(ChunkMapType::SamebytesMap)?;
                    self.read_state = ReadState::LastChunkSamebytesMapOfObject;
                },

                ReadState::LastChunkSamebytesMapOfObject => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::LastChunkSamebytesMapOfObject");
                    // reads the chunkmap if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_chunk_samebytes_map, 
                        &mut self.in_progress_data.current_encoded_chunk_samebytes_map_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };

                    // prepare and switch to the next state
                    // write the chunk deduplication map even there is some space left in map to ensure
                    // that this map will be written if there is no next object.
                    self.flush_chunkmap(ChunkMapType::DeduplicationMap)?;
                    self.read_state = ReadState::LastChunkDeduplicationMapOfObject;
                },

                ReadState::LastChunkDeduplicationMapOfObject => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::LastChunkDeduplicationMapOfObject");
                    // reads the chunkmap if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_chunk_deduplication_map, 
                        &mut self.in_progress_data.current_encoded_chunk_deduplication_map_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };

                    // prepare and switch to the next state
                    // this will only fail in case of encryption errrors - which should be happend before
                    let object_footer = match self.current_object_encoder.get_encoded_footer() {
                        Ok(obj_footer) => obj_footer,
                        Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                    };
                    self.in_progress_data.segment_footer.add_object_footer_offset(
                        self.current_object_encoder.obj_number(), 
                        self.in_progress_data.bytes_read.current_segment);
                    self.in_progress_data.current_encoded_object_footer = object_footer;
                    self.in_progress_data.current_encoded_object_footer_read_bytes = ReadBytes::NotRead;
                    self.in_progress_data.main_footer.object_footer.insert(self.current_object_encoder.obj_number(), self.current_segment_no());
                    self.read_state = ReadState::ObjectFooter;
                },

                ReadState::Chunking => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::Chunking");
                    let current_chunk_number = self.current_object_encoder.current_chunk_number();

                    // reads the chunking data
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_chunked_data, 
                        &mut self.in_progress_data.current_encoded_chunked_data_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };

                    // check the read bytes (for segment length)
                    // TODO: calculate also the sizes of the current chunkmaps
                    if self.in_progress_data.bytes_read.current_segment >= self.optional_parameters.target_segment_size.unwrap_or(u64::MAX) {
                        // set the appropriate segmentation state to full (with the next segment number)
                        self.segmentation_state = match self.segmentation_state {
                            SegmentationState::Partial(segment_number) => SegmentationState::Full(segment_number),
                            _ => unreachable!(),
                        };
                        // flush the first chunkmap and set the appropriate read state
                        self.flush_chunkmap(ChunkMapType::OffsetMap)?;
                        self.read_state = ReadState::ChunkOffsetMap;
                        continue;
                    }

                    // check if the chunkmaps are full - this lines are necessary to ensure
                    // the correct file footer offset is set while e.g. reading a bunch of empty files.
                    if self.check_chunkmap_is_full_and_flush(ChunkMapType::OffsetMap)? {
                        self.read_state = ReadState::ChunkOffsetMap;
                        continue;
                    };

                    if self.check_chunkmap_is_full_and_flush(ChunkMapType::SizeMap)? {
                        self.read_state = ReadState::ChunkSizeMap;
                        continue;
                    };

                    if self.check_chunkmap_is_full_and_flush(ChunkMapType::FlagsMap)? {
                        self.read_state = ReadState::ChunkFlagsMap;
                        continue;
                    };

                    if self.check_chunkmap_is_full_and_flush(ChunkMapType::XxHashMap)? {
                        self.read_state = ReadState::ChunkXxHashMap;
                        continue;
                    };

                    if self.check_chunkmap_is_full_and_flush(ChunkMapType::SamebytesMap)? {
                        self.read_state = ReadState::ChunkSamebytesMap;
                        continue;
                    };

                    if self.check_chunkmap_is_full_and_flush(ChunkMapType::DeduplicationMap)? {
                        self.read_state = ReadState::ChunkDeduplicationMap;
                        continue;
                    };
                    // handles the prepared data queue
                    loop {
                        match self.in_progress_data.current_prepared_data_queue_state {
                            PreparedDataQueueState::None => {
                                // read next chunk
                                let data = match self.current_object_encoder.get_next_data(
                                    self.in_progress_data.bytes_read.current_segment,
                                    self.current_segment_no(),
                                    self.optional_parameters.deduplication_chunkmap.as_mut()) {
                                        Ok(data) => data,
                                        Err(e) => match e.get_kind() {
                                            ZffErrorKind::ReadEOF => {
                                                // write the chunk offset map even there is some space left in map to ensure
                                                // that this map will be written if there is no next object.
                                                self.flush_chunkmap(ChunkMapType::OffsetMap)?;
                                                self.read_state = ReadState::LastChunkOffsetMapOfObject;
                                                break;
                                            },
                                            _ => {
                                                return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
                                            }
                                        }
                                };

                                match data {
                                    PreparedData::PreparedChunk(_) => {
                                        if !self.in_progress_data.chunkmaps.offset_map.add_chunk_entry(
                                            current_chunk_number, self.in_progress_data.bytes_read.current_segment) {
                                            self.flush_chunkmap(ChunkMapType::OffsetMap)?;
                                            self.read_state = ReadState::ChunkOffsetMap;
                                            self.in_progress_data.chunkmaps.offset_map.add_chunk_entry(
                                                current_chunk_number, self.in_progress_data.bytes_read.current_segment);
                                        }
                                        self.in_progress_data.current_prepared_data_queue_state = PreparedDataQueueState::Flags;
                                    },
                                    _ => {
                                        self.in_progress_data.current_prepared_data_queue_state = PreparedDataQueueState::Data;
                                    },
                                }
                                self.in_progress_data.current_prepared_data_queue = Some(data);
                            },
                            PreparedDataQueueState::Flags => {
                                let flags = match &self.in_progress_data.current_prepared_data_queue {
                                    Some(prepared_data) => match prepared_data {
                                        PreparedData::PreparedChunk(prepared_chunk) => prepared_chunk.flags().clone(),
                                        _ => {
                                            self.in_progress_data.current_prepared_data_queue_state = PreparedDataQueueState::Data;
                                            continue;
                                        },
                                    },
                                    None => unreachable!(),
                                };
                                if !self.in_progress_data.chunkmaps.flags_map.add_chunk_entry(current_chunk_number, &flags) {
                                    self.flush_chunkmap(ChunkMapType::FlagsMap)?;
                                    self.read_state = ReadState::ChunkFlagsMap;
                                    self.in_progress_data.chunkmaps.flags_map.add_chunk_entry(current_chunk_number,&flags);
                                    continue 'read_loop;
                                }
                                self.in_progress_data.current_prepared_data_queue_state = PreparedDataQueueState::Size;
                            },
                            PreparedDataQueueState::Size => {
                                let size = match &self.in_progress_data.current_prepared_data_queue {
                                    Some(prepared_data) => match prepared_data {
                                        PreparedData::PreparedChunk(prepared_chunk) => prepared_chunk.size(),
                                        _ => {
                                            self.in_progress_data.current_prepared_data_queue_state = PreparedDataQueueState::Data;
                                            continue;
                                        },
                                    },
                                    None => unreachable!(),
                                };
                                if !self.in_progress_data.chunkmaps.size_map.add_chunk_entry(current_chunk_number, size) {
                                    self.flush_chunkmap(ChunkMapType::SizeMap)?;
                                    self.read_state = ReadState::ChunkSizeMap;
                                    self.in_progress_data.chunkmaps.size_map.add_chunk_entry(current_chunk_number, size);
                                    continue 'read_loop;
                                }
                                self.in_progress_data.current_prepared_data_queue_state = PreparedDataQueueState::XxHash;
                            },
                            PreparedDataQueueState::XxHash => {
                                let xxhash = match self.in_progress_data.current_prepared_data_queue.clone() {
                                    Some(prepared_data) => match prepared_data {
                                        PreparedData::PreparedChunk(prepared_chunk) => prepared_chunk.xxhash().clone(),
                                        _ => {
                                            self.in_progress_data.current_prepared_data_queue_state = PreparedDataQueueState::Data;
                                            continue;
                                        },
                                    },
                                    None => unreachable!(),
                                };
                                if !self.in_progress_data.chunkmaps.xxhash_map.add_chunk_entry(current_chunk_number, xxhash) {
                                    self.flush_chunkmap(ChunkMapType::XxHashMap)?;
                                    self.read_state = ReadState::ChunkXxHashMap;
                                    self.in_progress_data.chunkmaps.xxhash_map.add_chunk_entry(current_chunk_number, xxhash);
                                    continue 'read_loop;
                                }
                                self.in_progress_data.current_prepared_data_queue_state = PreparedDataQueueState::SameBytes;
                            },
                            PreparedDataQueueState::SameBytes => {
                                let samebytes = match &self.in_progress_data.current_prepared_data_queue {
                                    Some(prepared_data) => match prepared_data {
                                        PreparedData::PreparedChunk(prepared_chunk) => prepared_chunk.samebytes().clone(),
                                        _ => unreachable!(),
                                    },
                                    None => unreachable!(),
                                };
                                if let Some(samebytes) = samebytes {
                                    if !self.in_progress_data.chunkmaps.same_bytes_map.add_chunk_entry(current_chunk_number, samebytes) {
                                        self.flush_chunkmap(ChunkMapType::SamebytesMap)?;
                                        self.read_state = ReadState::ChunkSamebytesMap;
                                        self.in_progress_data.chunkmaps.same_bytes_map.add_chunk_entry(current_chunk_number, samebytes);
                                        continue 'read_loop;
                                    }
                                }
                                self.in_progress_data.current_prepared_data_queue_state = PreparedDataQueueState::Deduplication;
                                continue;
                            },
                            PreparedDataQueueState::Deduplication => {
                                let deduplication = match &self.in_progress_data.current_prepared_data_queue {
                                    Some(prepared_data) => match prepared_data {
                                        PreparedData::PreparedChunk(prepared_chunk) => prepared_chunk.duplicated().clone(),
                                        _ => unreachable!(),
                                    },
                                    None => unreachable!(),
                                };
                                if let Some(deduplication) = deduplication {
                                    if !self.in_progress_data.chunkmaps.duplicate_chunks.add_chunk_entry(current_chunk_number, deduplication) {
                                        self.flush_chunkmap(ChunkMapType::DeduplicationMap)?;
                                        self.read_state = ReadState::ChunkDeduplicationMap;
                                        self.in_progress_data.chunkmaps.duplicate_chunks.add_chunk_entry(current_chunk_number, deduplication);
                                        continue 'read_loop;
                                    }
                                }
                                self.in_progress_data.current_prepared_data_queue_state = PreparedDataQueueState::Data;
                                continue;
                            },
                            PreparedDataQueueState::Data => {
                                let data = match &self.in_progress_data.current_prepared_data_queue {
                                    Some(prepared_data) => match prepared_data {
                                        PreparedData::PreparedChunk(prepared_chunk) => prepared_chunk.data(),
                                        PreparedData::PreparedFileHeader(ref prepared_file_header) => prepared_file_header,
                                        PreparedData::PreparedFileFooter(ref prepared_file_footer) => prepared_file_footer,
                                    },
                                    None => unreachable!(),
                                };
                                self.in_progress_data.current_encoded_chunked_data = data.to_vec();
                                self.in_progress_data.current_encoded_chunked_data_read_bytes = ReadBytes::NotRead;
                                self.in_progress_data.current_prepared_data_queue_state = PreparedDataQueueState::None;
                                self.in_progress_data.current_prepared_data_queue = None;
                                break;
                            },
                        }
                    }
                },
                ReadState::ObjectFooter => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::ObjectFooter");
                    // reads the current object footer if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_object_footer, 
                        &mut self.in_progress_data.current_encoded_object_footer_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };

                    // switch to the next state
                    self.current_object_encoder = match self.object_encoder.pop() {
                        Some(creator_obj_encoder) => creator_obj_encoder,
                        None => {
                            self.in_progress_data.segment_footer.set_footer_offset(self.in_progress_data.bytes_read.current_segment);
                            self.in_progress_data.segment_footer.set_length_of_segment(
                                self.in_progress_data.bytes_read.current_segment + 
                                self.in_progress_data.segment_footer.encode_directly().len() as u64 + 
                                self.in_progress_data.main_footer.encode_directly().len() as u64);
                            self.in_progress_data.current_encoded_segment_footer = self.in_progress_data.segment_footer.encode_directly();
                            self.in_progress_data.current_encoded_segment_footer_read_bytes = ReadBytes::NotRead;
                            self.segmentation_state = SegmentationState::FullLastSegment(self.current_segment_no());
                            self.read_state = ReadState::SegmentFooter;
                            continue;
                        }
                    };
                    self.in_progress_data.main_footer.object_header.insert(self.current_object_encoder.obj_number(), self.current_segment_no());
                    self.read_state = ReadState::ObjectHeader;
                    self.in_progress_data.current_encoded_object_header = self.current_object_encoder.get_encoded_header();
                    self.in_progress_data.segment_footer.add_object_header_offset(
                        self.current_object_encoder.obj_number(),
                        self.in_progress_data.bytes_read.current_segment);
                },
                ReadState::SegmentFooter => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::SegmentFooter");
                    // reads the current segment footer if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_segment_footer, 
                        &mut self.in_progress_data.current_encoded_segment_footer_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };

                    // switch to the next state
                    self.in_progress_data.main_footer.set_footer_offset(self.in_progress_data.bytes_read.current_segment);
                    self.in_progress_data.main_footer.set_number_of_segments(self.current_segment_no());
                    self.in_progress_data.encoded_main_footer = self.in_progress_data.main_footer.encode_directly();
                    self.in_progress_data.encoded_main_footer_read_bytes = ReadBytes::NotRead;
                    
                    match self.segmentation_state {
                        SegmentationState::Full(segment_number) => self.segmentation_state = SegmentationState::Finished(segment_number),
                        SegmentationState::Partial(_) => unreachable!(),
                        SegmentationState::Finished(_) => unreachable!(),
                        SegmentationState::FullLastSegment(_) => self.read_state = ReadState::MainFooter,
                        SegmentationState::FinishedLastSegment(_) => unreachable!(),
                    }
                },
                ReadState::MainFooter => {
                    #[cfg(feature = "log")]
                    trace!("ReadState::MainFooter");
                    // reads the main footer if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.encoded_main_footer, 
                        &mut self.in_progress_data.encoded_main_footer_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer < buf_len {
                        self.segmentation_state = SegmentationState::FinishedLastSegment(self.current_segment_no());
                    }
                    return Ok(bytes_written_to_buffer);
                }
            }
        }
    }
}

fn setup_container<R: Read>(
    physical_objects: HashMap<ObjectHeader, R>,
    logical_objects: HashMap<ObjectHeader, Vec<PathBuf>>,
    hash_types: Vec<HashType>,
    params: ZffCreationParameters,
    output: ZffFilesOutput) -> Result<ZffWriter<R>> {
    let mut physical_objects = physical_objects;
    let mut logical_objects = logical_objects;

    let mut total_bytes_read = 0;

    // check if an existing container should be extended or a new container should be created
    let extender_parameter = match output {
        ZffFilesOutput::ExtendContainer(ref files_to_extend) => {
            let mut extension_parameter = None;
            for ext_file in files_to_extend {
                let mut raw_segment = File::open(ext_file)?;
                if let Ok(mf) = decode_main_footer(&mut raw_segment) {
                    let current_segment = ext_file.to_path_buf();
                    
                    let segment = Segment::new_from_reader(&raw_segment)?;
                    //self.segmentation_state = SegmentationState::Partial(segment.header().segment_number);
                    let segment_number = segment.header().segment_number;
                    let initial_chunk_number = match segment.footer().chunk_offset_map_table.keys().max() {
                        Some(x) => *x + 1,
                        None => return Err(ZffError::new(ZffErrorKind::NoChunksLeft, ""))
                    };
                    let next_object_no = match mf.object_footer().keys().max() {
                        Some(x) => *x + 1,
                        None => return Err(ZffError::new(ZffErrorKind::NoObjectsLeft, "")),
                    };
                    let segment_footer = segment.footer().clone();
    
                    extension_parameter = Some(ZffExtenderParameter::with_data(
                        current_segment,
                        next_object_no,
                        initial_chunk_number,
                        segment_number,
                        segment_footer,
                        mf,
                    ));
                    total_bytes_read += raw_segment.seek(SeekFrom::End(0))?;
                    raw_segment.seek(SeekFrom::Start(0))?;
                }
                // try to decode the segment header to check if the file is a valid segment.
                let _ = Segment::new_from_reader(raw_segment)?;
            }
            extension_parameter
        },
        _ => None
    };

    //initially check if all EncryptionHeader are contain a decrypted encryption key for physical and logical objects.
    // uses check_encryption_key_in_header for all ObjectHeader in physical_objects and logical_objects:
    prepare_object_header(&mut physical_objects, &mut logical_objects, &extender_parameter)?;

    let signature_key_bytes = &params.signature_key.as_ref().map(|signing_key| signing_key.to_bytes().to_vec());
    let mut object_encoder = Vec::with_capacity(physical_objects.len()+logical_objects.len());

    let initial_chunk_number = if let Some(extender_parameter) = &extender_parameter {
        extender_parameter.initial_chunk_number
    } else {
        INITIAL_CHUNK_NUMBER
    };

    setup_physical_object_encoder(
        physical_objects,
        &hash_types,
        signature_key_bytes,
        initial_chunk_number,
        &mut object_encoder)?;

    setup_logical_object_encoder(
        logical_objects,
        &hash_types,
        signature_key_bytes,
        initial_chunk_number,
        &mut object_encoder)?;

    object_encoder.reverse();
    let mut current_object_encoder = match object_encoder.pop() {
        Some(creator_obj_encoder) => creator_obj_encoder,
        None => return Err(ZffError::new(ZffErrorKind::NoObjectsLeft, "")),
    };

    let mut segmentation_state = SegmentationState::default();

    let mut in_progress_data = build_in_progress_data(&params);
    let mut output = output;

    let read_state = if let Some(_) = &extender_parameter {
        ReadState::ObjectHeader
    } else {
        ReadState::SegmentHeader
    };

    if let Some(extender_parameter) = extender_parameter {
        let mut file = OpenOptions::new().append(true).read(true).open(&extender_parameter.current_segment)?;
        let offset = file.seek(SeekFrom::End(0))?;
        in_progress_data.bytes_read.current_segment = offset;
        in_progress_data.current_encoded_object_header = current_object_encoder.get_encoded_header();
        in_progress_data.segment_footer = extender_parameter.segment_footer;
        in_progress_data.segment_footer.add_object_header_offset(
            current_object_encoder.obj_number(),
            in_progress_data.bytes_read.current_segment);
        segmentation_state = SegmentationState::Partial(extender_parameter.segment_number);
        in_progress_data.main_footer = extender_parameter.main_footer;
        output = ZffFilesOutput::ExtendContainer(vec![extender_parameter.current_segment]);
        in_progress_data.bytes_read.total = total_bytes_read;
        in_progress_data.encoded_segment_header_read_bytes = ReadBytes::Finished;
        in_progress_data.main_footer.object_header.insert(current_object_encoder.obj_number(), extender_parameter.segment_number);
    }

    Ok(ZffWriter {
        read_state,
        object_encoder,
        current_object_encoder,
        in_progress_data,
        segmentation_state,
        optional_parameters: params,
        output
    })
}

fn build_in_progress_data(params: &ZffCreationParameters) -> ZffWriterInProgressData {
    let mut in_progress_data = ZffWriterInProgressData::new();
    in_progress_data.main_footer.description_notes = params.description_notes.clone();

    // setup default chunkmap_size if not set in parameters
    let chunkmap_size = params.chunkmap_size.unwrap_or(DEFAULT_CHUNKMAP_SIZE);

    // setup the segment header
    let segment_header = SegmentHeader::new(params.unique_identifier, INITIAL_SEGMENT_NUMBER, chunkmap_size);
    let encoded_segment_header = segment_header.encode_directly();
    in_progress_data.encoded_segment_header = encoded_segment_header;
    
    // set chunkmaps target size
    in_progress_data.chunkmaps.offset_map.set_target_size(chunkmap_size as usize);
    in_progress_data.chunkmaps.size_map.set_target_size(chunkmap_size as usize);
    in_progress_data.chunkmaps.flags_map.set_target_size(chunkmap_size as usize);
    in_progress_data.chunkmaps.xxhash_map.set_target_size(chunkmap_size as usize);
    in_progress_data.chunkmaps.same_bytes_map.set_target_size(chunkmap_size as usize);
    in_progress_data.chunkmaps.duplicate_chunks.set_target_size(chunkmap_size as usize);

    in_progress_data
}

fn fill_buffer(in_progress_data: &[u8], in_progress_data_read_bytes: &mut ReadBytes, buf: &mut [u8], bytes_written_to_buffer: &mut usize) -> std::io::Result<usize> {
    let mut bytes_read = 0;
    match in_progress_data_read_bytes {
        ReadBytes::NotRead => {
            let data_length = in_progress_data.len();
            let bytes_to_read = (buf.len()-*bytes_written_to_buffer).min(data_length);
            buf[*bytes_written_to_buffer..bytes_to_read+*bytes_written_to_buffer].copy_from_slice(&in_progress_data[..bytes_to_read]);
            bytes_read = bytes_to_read;
            *bytes_written_to_buffer += bytes_to_read;
            *in_progress_data_read_bytes = if bytes_to_read == data_length {
                ReadBytes::Finished
            } else {
                ReadBytes::Read(bytes_to_read as u64)
            };
        }
        ReadBytes::Read(read) => {
            let data_length = in_progress_data.len();
            let bytes_to_read = (buf.len()-*bytes_written_to_buffer).min(data_length - *read as usize);
            buf[*bytes_written_to_buffer..bytes_to_read+*bytes_written_to_buffer].copy_from_slice(&in_progress_data[*read as usize..*read as usize + bytes_to_read]);
            bytes_read = bytes_to_read;
            *bytes_written_to_buffer += bytes_to_read;
            *in_progress_data_read_bytes = if *read + bytes_to_read as u64 == data_length as u64 {
                ReadBytes::Finished
            } else {
                ReadBytes::Read(*read + bytes_to_read as u64)
            };
        }
        ReadBytes::Finished => {},
    }
    Ok(bytes_read)
}

fn decode_main_footer<R: Read + Seek>(raw_segment: &mut R) -> Result<MainFooter> {
	raw_segment.seek(SeekFrom::End(-8))?;
	let footer_offset = u64::decode_directly(raw_segment)?;
	raw_segment.seek(SeekFrom::Start(footer_offset))?;
	match MainFooter::decode_directly(raw_segment) {
		Ok(mf) => {
			raw_segment.rewind()?;
			Ok(mf)
		},
		Err(e) => match e.get_kind() {
			ZffErrorKind::HeaderDecodeMismatchIdentifier => {
				raw_segment.rewind()?;
				Err(e)
			},
			_ => Err(e)
		}
	}
}