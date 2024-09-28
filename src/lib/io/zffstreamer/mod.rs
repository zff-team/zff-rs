// Parent
use super::*;

// - internal
use crate::{
    footer::SegmentFooter, header::{ChunkMapType, ChunkMaps, SegmentHeader},
    HeaderCoding,
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
    ChunkCrcMap,
    ChunkSamebytesMap,
    ChunkDeduplicationMap,
    LastChunkOffsetMapOfObject,
    LastChunkSizeMapOfObject,
    LastChunkFlagsMapOfObject,
    LastChunkCrcMapOfObject,
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
	Crc,
    SameBytes,
    Deduplication,
	Data,
    #[default]
	None,
}

// - external
#[cfg(feature = "log")]
use log::trace;


#[derive(Debug, Clone, Default)]
struct ZffStreamerInProgressData {
    bytes_read: u64, // the number of bytes read from this streamer,
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
    current_encoded_chunk_crc_map: Vec<u8>, // the current encoded chunk crc map,
    current_encoded_chunk_crc_map_read_bytes: ReadBytes, // the number of bytes read from the current encoded chunk crc map,
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

impl ZffStreamerInProgressData {
    fn new() -> Self {
        Self {
            current_encoded_chunk_offset_map_read_bytes: ReadBytes::Finished,
            current_encoded_chunk_size_map_read_bytes: ReadBytes::Finished,
            current_encoded_chunk_flags_map_read_bytes: ReadBytes::Finished,
            current_encoded_chunk_crc_map_read_bytes: ReadBytes::Finished,
            ..Default::default()
        }
    }
}

/// ZffStreamer is a struct that is used to create a new zff container while using the appropriate Read implementation of this struct.
/// 
/// ZffStreamer only supports to create a new zff container in a single segment.
/// For creating a multi-segment zff container, or extending an existing one, use the ZffWriter struct.
pub struct ZffStreamer<R: Read> {
    object_encoder: Vec<ObjectEncoderInformation<R>>,
	current_object_encoder: ObjectEncoderInformation<R>, //the current object encoder
    /// The field target_segment_size will be ignored.
    optional_parameters: ZffCreationParameters,
    in_progress_data: ZffStreamerInProgressData,
    read_state: ReadState,
}

impl<R: Read> ZffStreamer<R> {
    /// Returns a new ZffStreamer with the given values.
    pub fn with_data(
        physical_objects: HashMap<ObjectHeader, R>, // <ObjectHeader, input_data stream>
		logical_objects: HashMap<ObjectHeader, Vec<PathBuf>>, //<ObjectHeader, input_files>
		hash_types: Vec<HashType>,
        params: ZffCreationParameters,
    ) -> Result<Self> {

        let mut physical_objects = physical_objects;
        let mut logical_objects = logical_objects;

        //initially check if all EncryptionHeader are contain a decrypted encryption key for physical and logical objects.
        // uses check_encryption_key_in_header for all ObjectHeader in physical_objects and logical_objects:
        prepare_object_header(&mut physical_objects, &mut logical_objects, &None)?;

        let signature_key_bytes = &params.signature_key.as_ref().map(|signing_key| signing_key.to_bytes().to_vec());
		let mut object_encoder = Vec::with_capacity(physical_objects.len()+logical_objects.len());

        setup_physical_object_encoder(
			physical_objects,
			&hash_types,
			signature_key_bytes,
			INITIAL_CHUNK_NUMBER,
			&mut object_encoder)?;

		setup_logical_object_encoder(
			logical_objects,
			&hash_types,
			signature_key_bytes,
			INITIAL_CHUNK_NUMBER,
			&mut object_encoder)?;

        object_encoder.reverse();
        let current_object_encoder = match object_encoder.pop() {
            Some(creator_obj_encoder) => creator_obj_encoder,
            None => return Err(ZffError::new(ZffErrorKind::NoObjectsLeft, "")),
        };

        Ok(Self {
            read_state: ReadState::SegmentHeader,
            object_encoder,
            current_object_encoder,
            in_progress_data: build_in_progress_data(&params),
            optional_parameters: params,
        })
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


    /// Returns true if the chunkmap was full and flushed.
    fn check_chunkmap_is_full_and_flush(&mut self, chunk_map_type: ChunkMapType) -> bool {
        match chunk_map_type {
            ChunkMapType::OffsetMap => {
                if self.in_progress_data.chunkmaps.offset_map.is_full() {
                    self.flush_chunkmap(chunk_map_type);
                    true
                } else {
                    false
                }
            },
            ChunkMapType::SizeMap => {
                if self.in_progress_data.chunkmaps.size_map.is_full() {
                    self.flush_chunkmap(chunk_map_type);
                    true
                } else {
                    false
                }
            },
            ChunkMapType::FlagsMap => {
                if self.in_progress_data.chunkmaps.flags_map.is_full() {
                    self.flush_chunkmap(chunk_map_type);
                    true
                } else {
                    false
                }
            },
            ChunkMapType::CRCMap => {
                if self.in_progress_data.chunkmaps.crc_map.is_full() {
                    self.flush_chunkmap(chunk_map_type);
                    true
                } else {
                    false
                }
            },
            ChunkMapType::SamebytesMap => {
                if self.in_progress_data.chunkmaps.same_bytes_map.is_full() {
                    self.flush_chunkmap(chunk_map_type);
                    true
                } else {
                    false
                }
            },
            ChunkMapType::DeduplicationMap => {
                if self.in_progress_data.chunkmaps.duplicate_chunks.is_full() {
                    self.flush_chunkmap(chunk_map_type);
                    true
                } else {
                    false
                }
            },
        }
    }

    /// flushes the current chunkmap.
    fn flush_chunkmap(&mut self, chunk_map_type: ChunkMapType) {
        match chunk_map_type {
            ChunkMapType::OffsetMap => {
                if let Some(chunk_no) = self.in_progress_data.chunkmaps.offset_map.chunkmap().keys().max() {
                    self.in_progress_data.main_footer.chunk_offset_maps.insert(*chunk_no, INITIAL_SEGMENT_NUMBER);
                    self.in_progress_data.segment_footer.chunk_offset_map_table.insert(*chunk_no, self.in_progress_data.bytes_read);
                }
                self.in_progress_data.current_encoded_chunk_offset_map = self.in_progress_data.chunkmaps.offset_map.encode_directly();
                self.in_progress_data.current_encoded_chunk_offset_map_read_bytes = ReadBytes::NotRead;
                self.in_progress_data.chunkmaps.offset_map.flush();
            },
            ChunkMapType::SizeMap => {
                if let Some(chunk_no) = self.in_progress_data.chunkmaps.size_map.chunkmap().keys().max() {
                    self.in_progress_data.main_footer.chunk_size_maps.insert(*chunk_no, INITIAL_SEGMENT_NUMBER);
                    self.in_progress_data.segment_footer.chunk_size_map_table.insert(*chunk_no, self.in_progress_data.bytes_read);
                }
                self.in_progress_data.current_encoded_chunk_size_map = self.in_progress_data.chunkmaps.size_map.encode_directly();
                self.in_progress_data.current_encoded_chunk_size_map_read_bytes = ReadBytes::NotRead;
                self.in_progress_data.chunkmaps.size_map.flush();
            },
            ChunkMapType::FlagsMap => {
                if let Some(chunk_no) = self.in_progress_data.chunkmaps.flags_map.chunkmap().keys().max() {
                    self.in_progress_data.main_footer.chunk_flags_maps.insert(*chunk_no, INITIAL_SEGMENT_NUMBER);
                    self.in_progress_data.segment_footer.chunk_flags_map_table.insert(*chunk_no, self.in_progress_data.bytes_read);
                }
                self.in_progress_data.current_encoded_chunk_flags_map = self.in_progress_data.chunkmaps.flags_map.encode_directly();
                self.in_progress_data.current_encoded_chunk_flags_map_read_bytes = ReadBytes::NotRead;
                self.in_progress_data.chunkmaps.flags_map.flush();
            },
            ChunkMapType::CRCMap => {
                if let Some(chunk_no) = self.in_progress_data.chunkmaps.crc_map.chunkmap().keys().max() {
                    self.in_progress_data.main_footer.chunk_crc_maps.insert(*chunk_no, INITIAL_SEGMENT_NUMBER);
                    self.in_progress_data.segment_footer.chunk_crc_map_table.insert(*chunk_no, self.in_progress_data.bytes_read);
                }
                self.in_progress_data.current_encoded_chunk_crc_map = self.in_progress_data.chunkmaps.crc_map.encode_directly();
                self.in_progress_data.current_encoded_chunk_crc_map_read_bytes = ReadBytes::NotRead;
                self.in_progress_data.chunkmaps.crc_map.flush();
            },
            ChunkMapType::SamebytesMap => {
                if let Some(chunk_no) = self.in_progress_data.chunkmaps.same_bytes_map.chunkmap().keys().max() {
                    self.in_progress_data.main_footer.chunk_samebytes_maps.insert(*chunk_no, INITIAL_SEGMENT_NUMBER);
                    self.in_progress_data.segment_footer.chunk_samebytes_map_table.insert(*chunk_no, self.in_progress_data.bytes_read);
                }
                self.in_progress_data.current_encoded_chunk_samebytes_map = self.in_progress_data.chunkmaps.same_bytes_map.encode_directly();
                self.in_progress_data.current_encoded_chunk_samebytes_map_read_bytes = ReadBytes::NotRead;
                self.in_progress_data.chunkmaps.same_bytes_map.flush();
            },
            ChunkMapType::DeduplicationMap => {
                if let Some(chunk_no) = self.in_progress_data.chunkmaps.duplicate_chunks.chunkmap().keys().max() {
                    self.in_progress_data.main_footer.chunk_samebytes_maps.insert(*chunk_no, INITIAL_SEGMENT_NUMBER);
                    self.in_progress_data.segment_footer.chunk_samebytes_map_table.insert(*chunk_no, self.in_progress_data.bytes_read);
                }
                self.in_progress_data.current_encoded_chunk_deduplication_map = self.in_progress_data.chunkmaps.duplicate_chunks.encode_directly();
                self.in_progress_data.current_encoded_chunk_deduplication_map_read_bytes = ReadBytes::NotRead;
                self.in_progress_data.chunkmaps.duplicate_chunks.flush();
            },
        }
    }

}

impl<R: Read> Read for ZffStreamer<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut bytes_written_to_buffer = 0; // the number of bytes which are written to the current buffer,

        // may improve performance in different cases.
        let buf_len = buf.len();
        'read_loop: loop {
            match self.read_state {
                ReadState::SegmentHeader => {
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
                    self.read_state = ReadState::ObjectHeader;
                    // prepare the current object header
                    self.in_progress_data.current_encoded_object_header = self.current_object_encoder.get_encoded_header();
                    self.in_progress_data.segment_footer.add_object_header_offset(
                        self.current_object_encoder.obj_number(),
                        self.in_progress_data.bytes_read);
                },
                ReadState::ObjectHeader => {
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
                    self.read_state = ReadState::Chunking;
                },

                ReadState::ChunkSizeMap => {
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
                    self.read_state = ReadState::Chunking;
                },

                ReadState::ChunkFlagsMap => {
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
                    self.read_state = ReadState::Chunking;
                },

                ReadState::ChunkCrcMap => {
                    trace!("ReadState::ChunkCrcMap");
                    // reads the chunkmap if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_chunk_crc_map, 
                        &mut self.in_progress_data.current_encoded_chunk_crc_map_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };

                    // switch to the next state
                    self.read_state = ReadState::Chunking;
                },

                ReadState::ChunkSamebytesMap => {
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
                    self.read_state = ReadState::Chunking;
                },

                ReadState::ChunkDeduplicationMap => {
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
                    self.read_state = ReadState::Chunking;
                },

                ReadState::LastChunkOffsetMapOfObject => {
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
                    self.flush_chunkmap(ChunkMapType::SizeMap);
                    self.read_state = ReadState::LastChunkSizeMapOfObject;
                },

                ReadState::LastChunkSizeMapOfObject => {
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
                    self.flush_chunkmap(ChunkMapType::FlagsMap);
                    self.read_state = ReadState::LastChunkFlagsMapOfObject;
                },

                ReadState::LastChunkFlagsMapOfObject => {
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
                    // write the chunk crc map even there is some space left in map to ensure
                    // that this map will be written if there is no next object.
                    self.flush_chunkmap(ChunkMapType::CRCMap);
                    self.read_state = ReadState::LastChunkCrcMapOfObject;
                },

                ReadState::LastChunkCrcMapOfObject => {
                    trace!("ReadState::LastChunkCrcMapOfObject");
                    // reads the chunkmap if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_chunk_crc_map, 
                        &mut self.in_progress_data.current_encoded_chunk_crc_map_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if bytes_written_to_buffer >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };

                    // prepare and switch to the next state
                    // write the chunk samebytes map even there is some space left in map to ensure
                    // that this map will be written if there is no next object.
                    self.flush_chunkmap(ChunkMapType::SamebytesMap);
                    self.read_state = ReadState::LastChunkSamebytesMapOfObject;
                },

                ReadState::LastChunkSamebytesMapOfObject => {
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
                    self.flush_chunkmap(ChunkMapType::DeduplicationMap);
                    self.read_state = ReadState::LastChunkDeduplicationMapOfObject;
                },

                ReadState::LastChunkDeduplicationMapOfObject => {
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
                        self.in_progress_data.bytes_read);
                    self.in_progress_data.current_encoded_object_footer = object_footer;
                    self.in_progress_data.current_encoded_object_footer_read_bytes = ReadBytes::NotRead;
                    self.read_state = ReadState::ObjectFooter;
                },

                ReadState::Chunking => {
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
                    // check if the chunkmaps are full - this lines are necessary to ensure
                    // the correct file footer offset is set while e.g. reading a bunch of empty files.
                    if self.check_chunkmap_is_full_and_flush(ChunkMapType::OffsetMap) {
                        self.read_state = ReadState::ChunkOffsetMap;
                        continue;
                    };

                    if self.check_chunkmap_is_full_and_flush(ChunkMapType::SizeMap) {
                        self.read_state = ReadState::ChunkSizeMap;
                        continue;
                    };

                    if self.check_chunkmap_is_full_and_flush(ChunkMapType::FlagsMap) {
                        self.read_state = ReadState::ChunkFlagsMap;
                        continue;
                    };

                    if self.check_chunkmap_is_full_and_flush(ChunkMapType::CRCMap) {
                        self.read_state = ReadState::ChunkCrcMap;
                        continue;
                    };

                    if self.check_chunkmap_is_full_and_flush(ChunkMapType::SamebytesMap) {
                        self.read_state = ReadState::ChunkSamebytesMap;
                        continue;
                    };

                    if self.check_chunkmap_is_full_and_flush(ChunkMapType::DeduplicationMap) {
                        self.read_state = ReadState::ChunkDeduplicationMap;
                        continue;
                    };
                    // handles the prepared data queue
                    loop {
                        match self.in_progress_data.current_prepared_data_queue_state {
                            PreparedDataQueueState::None => {
                                // read next chunk
                                let data = match self.current_object_encoder.get_next_data(
                                    self.in_progress_data.bytes_read,
                                    INITIAL_SEGMENT_NUMBER,
                                    self.optional_parameters.deduplication_chunkmap.as_mut()) {
                                        Ok(data) => data,
                                        Err(e) => match e.get_kind() {
                                            ZffErrorKind::ReadEOF => {
                                                // write the chunk offset map even there is some space left in map to ensure
                                                // that this map will be written if there is no next object.
                                                self.flush_chunkmap(ChunkMapType::OffsetMap);
                                                self.read_state = ReadState::LastChunkOffsetMapOfObject;
                                                break;
                                            },
                                            _ => {
                                                return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
                                            }
                                        }
                                };

                                if !self.in_progress_data.chunkmaps.offset_map.add_chunk_entry(current_chunk_number, self.in_progress_data.bytes_read) {
                                    self.flush_chunkmap(ChunkMapType::OffsetMap);
                                    self.read_state = ReadState::ChunkOffsetMap;
                                    self.in_progress_data.chunkmaps.offset_map.add_chunk_entry(current_chunk_number, self.in_progress_data.bytes_read);
                                }
            
                                self.in_progress_data.current_prepared_data_queue = Some(data);
                                self.in_progress_data.current_prepared_data_queue_state = PreparedDataQueueState::Flags;
                                self.in_progress_data.current_encoded_chunked_data_read_bytes = ReadBytes::NotRead;
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
                                    self.flush_chunkmap(ChunkMapType::FlagsMap);
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
                                    self.flush_chunkmap(ChunkMapType::SizeMap);
                                    self.read_state = ReadState::ChunkSizeMap;
                                    self.in_progress_data.chunkmaps.size_map.add_chunk_entry(current_chunk_number, size);
                                    continue 'read_loop;
                                }
                                self.in_progress_data.current_prepared_data_queue_state = PreparedDataQueueState::Crc;
                            },
                            PreparedDataQueueState::Crc => {
                                let crc = match self.in_progress_data.current_prepared_data_queue.clone() {
                                    Some(prepared_data) => match prepared_data {
                                        PreparedData::PreparedChunk(prepared_chunk) => prepared_chunk.crc().clone(),
                                        _ => {
                                            self.in_progress_data.current_prepared_data_queue_state = PreparedDataQueueState::Data;
                                            continue;
                                        },
                                    },
                                    None => unreachable!(),
                                };
                                if !self.in_progress_data.chunkmaps.crc_map.add_chunk_entry(current_chunk_number, &crc) {
                                    self.flush_chunkmap(ChunkMapType::CRCMap);
                                    self.read_state = ReadState::ChunkCrcMap;
                                    self.in_progress_data.chunkmaps.crc_map.add_chunk_entry(current_chunk_number, &crc);
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
                                        self.flush_chunkmap(ChunkMapType::SamebytesMap);
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
                                        self.flush_chunkmap(ChunkMapType::DeduplicationMap);
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
                    self.in_progress_data.main_footer.object_header.insert(self.current_object_encoder.obj_number(), INITIAL_SEGMENT_NUMBER);
                    self.in_progress_data.main_footer.object_footer.insert(self.current_object_encoder.obj_number(), INITIAL_SEGMENT_NUMBER);
                    self.read_state = ReadState::ObjectHeader;
                    self.current_object_encoder = match self.object_encoder.pop() {
                        Some(creator_obj_encoder) => creator_obj_encoder,
                        None => {
                            self.in_progress_data.segment_footer.set_footer_offset(self.in_progress_data.bytes_read);
                            self.in_progress_data.segment_footer.set_length_of_segment(
                                self.in_progress_data.bytes_read + 
                                self.in_progress_data.segment_footer.encode_directly().len() as u64 + 
                                self.in_progress_data.main_footer.encode_directly().len() as u64);
                            self.in_progress_data.current_encoded_segment_footer = self.in_progress_data.segment_footer.encode_directly();
                            self.in_progress_data.current_encoded_segment_footer_read_bytes = ReadBytes::NotRead;
                            self.read_state = ReadState::SegmentFooter;
                            continue;
                        }
                    };
                    self.in_progress_data.current_encoded_object_header = self.current_object_encoder.get_encoded_header();
                    self.in_progress_data.segment_footer.add_object_header_offset(
                        self.current_object_encoder.obj_number(),
                        self.in_progress_data.bytes_read);
                },
                ReadState::SegmentFooter => {
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
                    self.in_progress_data.main_footer.set_footer_offset(self.in_progress_data.bytes_read);
                    self.in_progress_data.main_footer.set_number_of_segments(INITIAL_SEGMENT_NUMBER);
                    self.in_progress_data.encoded_main_footer = self.in_progress_data.main_footer.encode_directly();
                    self.in_progress_data.encoded_main_footer_read_bytes = ReadBytes::NotRead;
                    
                    self.read_state = ReadState::MainFooter;
                },
                ReadState::MainFooter => {
                    trace!("ReadState::MainFooter");
                    // reads the main footer if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.encoded_main_footer, 
                        &mut self.in_progress_data.encoded_main_footer_read_bytes, 
                        buf, 
                        &mut bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    return Ok(bytes_written_to_buffer);
                }
            }
        }
    }
}

fn build_in_progress_data(params: &ZffCreationParameters) -> ZffStreamerInProgressData {
    let mut in_progress_data = ZffStreamerInProgressData::new();

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
    in_progress_data.chunkmaps.crc_map.set_target_size(chunkmap_size as usize);
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