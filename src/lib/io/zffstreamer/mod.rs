// - STD
use std::io::Read;
use std::collections::HashMap;
use std::path::PathBuf;

// - internal
use crate::{
    error::{ZffError, ZffErrorKind}, 
    hashing::HashType, 
    header::{ObjectHeader, SegmentHeader, ChunkMap, ChunkHeader},
    footer::{SegmentFooter, MainFooter}, 
    HeaderCoding
};

use super::*;

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
    ChunkMap,
    ObjectFooter,
    SegmentFooter,
    MainFooter,
}

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
    chunkmap: ChunkMap, // The current chunkmap,
    current_encoded_chunkmap: Vec<u8>, // the current encoded chunkmap,
    current_encoded_chunkmap_read_bytes: ReadBytes, // the number of bytes read from the current encoded chunkmap,
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
            current_encoded_chunkmap_read_bytes: ReadBytes::Finished,
            ..Default::default()
        }
    }
}

/// ZffStreamer is a struct that is used to create a new zff container while using the appropriate Read implementation of this struct.
/// ZffStreamer only supports to create a new zff container in a single segment. For creating a multi-segment zff container, or extending an existing one, use the ZffWriter struct.
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


}

impl<R: Read> Read for ZffStreamer<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut bytes_written_to_buffer = 0; // the number of bytes which are written to the current buffer,

        // may improve performance in different cases.
        let buf_len = buf.len();

        loop {
            match self.read_state {
                ReadState::SegmentHeader => {
                    // reads the segment header if not already read
                    // this is the initial state.
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.encoded_segment_header, 
                        &mut self.in_progress_data.encoded_segment_header_read_bytes, 
                        buf, 
                        bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if read_bytes >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };
                    bytes_written_to_buffer += read_bytes;
                    
                    // switch to the next state
                    self.read_state = ReadState::ObjectHeader;
                    // prepare the current object header
                    self.in_progress_data.current_encoded_object_header = self.current_object_encoder.get_encoded_header();
                    self.in_progress_data.segment_footer.add_object_header_offset(
                        self.current_object_encoder.obj_number(),
                        self.in_progress_data.bytes_read);
                },
                ReadState::ObjectHeader => {
                    // reads the current object header if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_object_header, 
                        &mut self.in_progress_data.current_encoded_object_header_read_bytes, 
                        buf, 
                        bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if read_bytes >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };
                    bytes_written_to_buffer += read_bytes;
                },
                ReadState::ChunkMap => {
                    // reads the chunkmap if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_chunkmap, 
                        &mut self.in_progress_data.current_encoded_chunkmap_read_bytes, 
                        buf, 
                        bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if read_bytes >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };
                    bytes_written_to_buffer += read_bytes;

                    // switch to the next state
                    self.read_state = ReadState::Chunking;
                },
                ReadState::Chunking => {
                    // reads the chunking data
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_chunked_data, 
                        &mut self.in_progress_data.current_encoded_chunked_data_read_bytes, 
                        buf, 
                        bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if read_bytes >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };
                    bytes_written_to_buffer += read_bytes;

                    // check if the chunkmap is full - this lines are necessary to ensure
                    // the correct file footer offset is set while e.g. reading a bunch of empty files.
                    if self.in_progress_data.chunkmap.is_full() {
                        if let Some(chunk_no) = self.in_progress_data.chunkmap.chunkmap().keys().max() {
                            self.in_progress_data.main_footer.chunk_maps.insert(*chunk_no, INITIAL_SEGMENT_NUMBER);
                            self.in_progress_data.segment_footer.chunk_map_table.insert(*chunk_no, self.in_progress_data.bytes_read);
                        }
                        self.in_progress_data.current_encoded_chunkmap = self.in_progress_data.chunkmap.encode_directly();
                        self.in_progress_data.current_encoded_chunkmap_read_bytes = ReadBytes::NotRead;
                        self.in_progress_data.chunkmap.flush();
                        self.read_state = ReadState::ChunkMap;
                        continue;
                    };

                    let current_chunk_number = self.current_object_encoder.current_chunk_number();

                    // read next chunk
                    let data = match self.current_object_encoder.get_next_data(
                        self.in_progress_data.bytes_read,
                        INITIAL_SEGMENT_NUMBER,
                        self.optional_parameters.deduplication_chunkmap.as_mut()) {
                            Ok(data) => data,
                            Err(e) => match e.get_kind() {
                                ZffErrorKind::ReadEOF => {
                                    // this will only fail in case of encryption errrors - which should be happend before
                                    let object_footer = match self.current_object_encoder.get_encoded_footer() {
                                        Ok(obj_footer) => obj_footer,
                                        Err(e) => return Err(std::io::Error::new(std::io::ErrorKind::Other, e)),
                                    };
                                    self.in_progress_data.segment_footer.add_object_footer_offset(self.current_object_encoder.obj_number(), self.in_progress_data.bytes_read);
                                    self.in_progress_data.current_encoded_object_footer = object_footer;
                                    self.in_progress_data.current_encoded_object_footer_read_bytes = ReadBytes::NotRead;
                                    self.read_state = ReadState::ObjectFooter;
                                    continue;
                                },
                                _ => {
                                    return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
                                }
                            }
                    };
                    
                    if ChunkHeader::check_identifier(&mut data.as_slice()) && // <-- checks if this is a chunk (and not e.g. a file footer or file header)
                    !self.in_progress_data.chunkmap.add_chunk_entry(current_chunk_number, self.in_progress_data.bytes_read) {
                        if let Some(chunk_no) = self.in_progress_data.chunkmap.chunkmap().keys().max() {
                            self.in_progress_data.main_footer.chunk_maps.insert(*chunk_no, INITIAL_SEGMENT_NUMBER);
                            self.in_progress_data.segment_footer.chunk_map_table.insert(*chunk_no, self.in_progress_data.bytes_read);
                        }
                        self.in_progress_data.current_encoded_chunkmap = self.in_progress_data.chunkmap.encode_directly();
                        self.in_progress_data.current_encoded_chunkmap_read_bytes = ReadBytes::NotRead;
                        self.in_progress_data.chunkmap.flush();
                        self.read_state = ReadState::ChunkMap;        
                        self.in_progress_data.chunkmap.add_chunk_entry(current_chunk_number, self.in_progress_data.bytes_read);
                    };

                    self.in_progress_data.current_encoded_chunked_data = data;
                    self.in_progress_data.current_encoded_chunked_data_read_bytes = ReadBytes::NotRead;
                },
                ReadState::ObjectFooter => {
                    // reads the current object footer if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_object_footer, 
                        &mut self.in_progress_data.current_encoded_object_footer_read_bytes, 
                        buf, 
                        bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if read_bytes >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };
                    bytes_written_to_buffer += read_bytes;

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
                    // reads the current segment footer if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.current_encoded_segment_footer, 
                        &mut self.in_progress_data.current_encoded_segment_footer_read_bytes, 
                        buf, 
                        bytes_written_to_buffer)?;
                    self.in_progress_data.bytes_read += read_bytes as u64;
                    if read_bytes >= buf_len {
                        return Ok(bytes_written_to_buffer);
                    };
                    bytes_written_to_buffer += read_bytes;

                    // switch to the next state
                    self.in_progress_data.main_footer.set_footer_offset(self.in_progress_data.bytes_read);
                    self.in_progress_data.main_footer.set_number_of_segments(INITIAL_SEGMENT_NUMBER);
                    self.in_progress_data.encoded_main_footer = self.in_progress_data.main_footer.encode_directly();
                    self.in_progress_data.encoded_main_footer_read_bytes = ReadBytes::NotRead;
                    
                    self.read_state = ReadState::MainFooter;
                },
                ReadState::MainFooter => {
                    // reads the main footer if not already read
                    let read_bytes = fill_buffer(
                        &self.in_progress_data.encoded_main_footer, 
                        &mut self.in_progress_data.encoded_main_footer_read_bytes, 
                        buf, 
                        bytes_written_to_buffer)?;
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
    in_progress_data.chunkmap.set_target_size(chunkmap_size as usize);

    in_progress_data
}

fn fill_buffer(in_progress_data: &[u8], in_progress_data_read_bytes: &mut ReadBytes, buf: &mut [u8], bytes_written_to_buffer: usize) -> std::io::Result<usize> {
    let mut bytes_read = 0;
    match in_progress_data_read_bytes {
        ReadBytes::NotRead => {
            let data_length = in_progress_data.len();
            let bytes_to_read = (buf.len()-bytes_written_to_buffer).min(data_length);
            buf[bytes_written_to_buffer..bytes_to_read].copy_from_slice(&in_progress_data[..bytes_to_read]);
            bytes_read = bytes_to_read;
            *in_progress_data_read_bytes = if bytes_to_read == data_length {
                ReadBytes::Finished
            } else {
                ReadBytes::Read(bytes_to_read as u64)
            };
        }
        ReadBytes::Read(read) => {
            let data_length = in_progress_data.len();
            let bytes_to_read = (buf.len()-bytes_written_to_buffer).min(data_length - *read as usize);
            buf[bytes_written_to_buffer..bytes_to_read].copy_from_slice(&in_progress_data[*read as usize..*read as usize + bytes_to_read]);
            bytes_read = bytes_to_read;
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