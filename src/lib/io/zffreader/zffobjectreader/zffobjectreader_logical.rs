// - STD
use std::collections::HashMap;
use std::io::{Error as IoError, ErrorKind as IoEKind, Read, Seek, SeekFrom};
use std::sync::Arc;

// - internal
use crate::prelude::*;
use crate::{
    FileMetadata,
    helper::copy_chunk_content_to_buf,
    io::zffreader::{ArcZffReaderMetadata, get_chunk_data},
};

// - external
#[cfg(feature = "log")]
use log::debug;
use moka::sync::Cache as MokaCache;

/// A reader which contains the appropriate metadata of a logical object
/// (e.g. the appropriate [ObjectHeader](crate::header::ObjectHeader) and [ObjectFooter](crate::footer::ObjectFooter)).
#[derive(Debug)]
pub(crate) struct ZffObjectReaderLogical<R: ReadAt> {
    metadata: ArcZffReaderMetadata<R>,
    object_header: ObjectHeader,
    object_footer: ObjectFooterLogical,
    active_file: u64,                  // filenumber of active file
    file_positions: HashMap<u64, u64>, //<filenumber, position>
    // this one is "redundant", the data is already available via the ArcZffReaderMetadata - but you can much more easier
    // access them with that additional hashmap.
    files: Arc<HashMap<u64, FileMetadata>>, //<filenumber, FileMetadata>
    reader_cache: MokaCache<u64, Arc<ChunkContent>>, //cache which holds the current chunk content (for performance purposes)
}

impl<R: ReadAt> ZffObjectReaderLogical<R> {
    /// Initialize the [ZffObjectReaderLogical].
    pub fn new(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Result<Self> {
        Self::with_obj_metadata(object_no, metadata)
    }

    /// Returns the appropriate [FileHeader](crate::header::FileHeader) of the current active file.
    pub fn current_fileheader(&self) -> Result<FileHeader> {
        let header_segment_number = match self
            .object_footer
            .file_header_segment_numbers
            .get(&self.active_file)
        {
            Some(no) => no,
            None => {
                return Err(ZffError::new(
                    ZffErrorKind::Missing,
                    format!(
                        "(current_fileheader) {ERROR_MISSING_FILE_NUMBER}{}",
                        self.active_file
                    ),
                ));
            }
        };
        let header_offset = match self
            .object_footer
            .file_header_offsets
            .get(&self.active_file)
        {
            Some(offset) => offset,
            None => {
                return Err(ZffError::new(
                    ZffErrorKind::EncodingError,
                    format!(
                        "{ERROR_UNREADABLE_OBJECT_HEADER_OFFSET_NO}{}",
                        self.object_header.object_number
                    ),
                ));
            }
        };
        let enc_info = if let Some(encryption_header) = &self.object_header.encryption_header {
            let key = match encryption_header.get_encryption_key() {
                Some(key) => key,
                None => {
                    return Err(ZffError::new(
                        ZffErrorKind::EncryptionError,
                        ERROR_MISSING_ENCRYPTION_HEADER_KEY,
                    ));
                }
            };
            Some(EncryptionInformation::new(
                key,
                encryption_header.algorithm.clone(),
            ))
        } else {
            None
        };
        match self.metadata.segments.get(header_segment_number) {
            None => Err(ZffError::new(
                ZffErrorKind::Missing,
                format!("{ERROR_MISSING_SEGMENT}{header_segment_number}"),
            )),
            Some(segment) => {
                //check encryption
                if let Some(enc_info) = &enc_info {
                    Ok(FileHeader::decode_at_encrypted_header_with_key(
                        segment,
                        *header_offset,
                        enc_info,
                    )?)
                } else {
                    Ok(FileHeader::decode_at(segment, *header_offset)?)
                }
            }
        }
    }

    fn with_obj_metadata(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Result<Self> {
        #[cfg(feature = "log")]
        debug!("Initialize logical object {}", object_no);
        let object_header = metadata.object_header(&object_no).unwrap().clone();
        let object_footer = match metadata.object_footer(&object_no) {
            Some(ObjectFooter::Logical(footer)) => footer.clone(),
            _ => unreachable!(), // already checked before in zffreader::initialize_unencrypted_object_reader();
        };

        let enc_info = if let Some(encryption_header) = &object_header.encryption_header {
            let key = match encryption_header.get_encryption_key() {
                Some(key) => key,
                None => {
                    return Err(ZffError::new(
                        ZffErrorKind::EncryptionError,
                        ERROR_MISSING_ENCRYPTION_HEADER_KEY,
                    ));
                }
            };
            Some(EncryptionInformation::new(
                key,
                encryption_header.algorithm.clone(),
            ))
        } else {
            None
        };

        // reads all file header and appropriate footer and fill the files-map/file_positions-map. Sets the File number 1 active.
        let mut files = HashMap::new();
        let mut file_positions = HashMap::new();
        for (filenumber, header_segment_number) in &object_footer.file_header_segment_numbers {
            #[cfg(feature = "log")]
            debug!("Initialize file {filenumber}");
            let header_offset = match object_footer.file_header_offsets.get(filenumber) {
                Some(offset) => offset,
                None => {
                    return Err(ZffError::new(
                        ZffErrorKind::Invalid,
                        ERROR_MALFORMED_SEGMENT,
                    ));
                }
            };
            let (footer_segment_number, footer_offset) =
                match object_footer.file_footer_segment_numbers.get(filenumber) {
                    None => {
                        return Err(ZffError::new(
                            ZffErrorKind::Invalid,
                            ERROR_MALFORMED_SEGMENT,
                        ));
                    }
                    Some(segment_no) => match object_footer.file_footer_offsets.get(filenumber) {
                        None => {
                            return Err(ZffError::new(
                                ZffErrorKind::Invalid,
                                ERROR_MALFORMED_SEGMENT,
                            ));
                        }
                        Some(offset) => (segment_no, offset),
                    },
                };
            let fileheader = match metadata.segments.get(header_segment_number) {
                None => {
                    return Err(ZffError::new(
                        ZffErrorKind::Missing,
                        format!("{ERROR_MISSING_SEGMENT}{header_segment_number}"),
                    ));
                }
                Some(segment) => {
                    //check encryption
                    if let Some(enc_info) = &enc_info {
                        FileHeader::decode_at_encrypted_header_with_key(
                            segment,
                            *header_offset,
                            enc_info,
                        )?
                    } else {
                        FileHeader::decode_at(segment, *header_offset)?
                    }
                }
            };
            let filefooter = match metadata.segments.get(footer_segment_number) {
                None => {
                    return Err(ZffError::new(
                        ZffErrorKind::Missing,
                        format!("{ERROR_MISSING_SEGMENT}{footer_segment_number}"),
                    ));
                }
                Some(segment) => {
                    //check encryption
                    if let Some(enc_info) = &enc_info {
                        FileFooter::decode_at_encrypted_footer_with_key(
                            segment,
                            *footer_offset,
                            enc_info,
                        )?
                    } else {
                        FileFooter::decode_at(segment, *footer_offset)?
                    }
                }
            };
            let metadata = FileMetadata::with_file_footer(fileheader, filefooter);
            files.insert(*filenumber, metadata);
            file_positions.insert(*filenumber, 0);
        }

        let files = Arc::new(files);
        #[cfg(feature = "log")]
        debug!(
            "{} files were successfully initialized for logical object {}.",
            files.len(),
            object_header.object_number
        );
        // unwrap is safe here, we've already used this before to obtain the appropriate object header and footer ;)
        metadata
            .object_metadata
            .get(&object_no)
            .unwrap()
            .get()
            .unwrap()
            .files
            .set(Arc::clone(&files))
            .map_err(|_| {
                ZffError::new(
                    ZffErrorKind::Invalid,
                    format!("object files already initialized: {object_no}"),
                )
            })?;

        Ok(Self {
            metadata,
            object_header,
            object_footer,
            active_file: 1,
            file_positions,
            files,
            reader_cache: MokaCache::builder()
                .max_capacity(DEFAULT_CHUNK_CACHE_CAPACITY)
                .build(),
        })
    }

    /// Returns a reference of the appropriate [ObjectHeader](crate::header::ObjectHeader).
    pub(crate) fn object_header_ref(&self) -> &ObjectHeader {
        &self.object_header
    }

    /// Returns the appropriate [ObjectFooter](crate::footer::ObjectFooter).
    pub(crate) fn object_footer(&self) -> ObjectFooter {
        ObjectFooter::Logical(self.object_footer.clone())
    }

    /// Sets the file of the appropriate filenumber active.
    /// # Error
    /// fails if no appropriate file for the given filenumber exists.
    pub fn set_active_file(&mut self, filenumber: u64) -> Result<()> {
        match self.files.get(&filenumber) {
            Some(_) => self.active_file = filenumber,
            None => {
                return Err(ZffError::new(
                    ZffErrorKind::Missing,
                    format!("(set_active_file) {ERROR_MISSING_FILE_NUMBER}{filenumber}"),
                ));
            }
        }
        Ok(())
    }

    /// Returns the [FileMetadata] of the active file.
    /// # Error
    /// Fails if no valid file is set as the active one.
    pub(crate) fn current_filemetadata(&self) -> Result<&FileMetadata> {
        self.filemetadata_by_filenumber(self.active_file)
    }

    /// Returns the [FileMetadata] for the given filenumber.
    /// # Error
    /// Fails if file not exists in object.
    pub(crate) fn filemetadata_by_filenumber(&self, file_number: u64) -> Result<&FileMetadata> {
        match self.files.get(&file_number) {
            Some(metadata) => Ok(metadata),
            None => Err(ZffError::new(
                ZffErrorKind::Missing,
                format!(
                    "(filemetadata) {ERROR_MISSING_FILE_NUMBER}{}",
                    self.active_file
                ),
            )),
        }
    }

    /// Returns a Reference of the inner files Hashmap
    pub(crate) fn files(&self) -> &HashMap<u64, FileMetadata> {
        &self.files
    }

    fn cached_chunk(&self, chunk_number: u64) -> std::io::Result<Arc<ChunkContent>> {
        if let Some(chunk_content) = self.reader_cache.get(&chunk_number) {
            return Ok(chunk_content);
        }

        let chunk_content = if let Some(samebyte) = self
            .metadata
            .preloaded_chunkmaps
            .read()
            .unwrap()
            .get_samebyte(chunk_number)
        {
            Arc::new(ChunkContent::SameBytes(samebyte))
        } else {
            let object_no = &self.object_header.object_number;
            Arc::new(get_chunk_data(
                object_no,
                Arc::clone(&self.metadata),
                chunk_number,
            )?)
        };
        self.reader_cache
            .insert(chunk_number, Arc::clone(&chunk_content));
        Ok(chunk_content)
    }
}

impl<R: ReadAt> ReadAtFile for ZffObjectReaderLogical<R> {
    fn read_at_file(&self, buf: &mut [u8], offset: u64, file_no: u64) -> std::io::Result<usize> {
        let filemetadata = self.files.get(&file_no).ok_or(IoError::other(format!(
            "{ERROR_MISSING_FILE_NUMBER}{}",
            file_no
        )))?;
        if buf.is_empty() || offset >= filemetadata.length_of_data() {
            return Ok(0);
        };

        let chunk_size = self.object_header.chunk_size;
        if chunk_size == 0 {
            return Err(IoError::new(IoEKind::InvalidData, ERROR_MALFORMED_SEGMENT));
        }

        let bytes_to_read = (buf.len() as u64).min(filemetadata.length_of_data() - offset) as usize;
        let mut read_bytes = 0;
        //unwrap is safe here: we've never initialized FileMetadata for ZffObjectReaderLogical with ::with_virtual_file_footer().
        let first_chunk_number = filemetadata.first_chunk_number().unwrap();

        while read_bytes < bytes_to_read {
            let current_offset = offset + read_bytes as u64;
            let current_chunk_number = first_chunk_number + current_offset / chunk_size;
            let inner_position = (current_offset % chunk_size) as usize;
            let remaining_in_chunk = chunk_size as usize - inner_position;
            let current_read_len = remaining_in_chunk.min(bytes_to_read - read_bytes);
            let chunk_content = self.cached_chunk(current_chunk_number)?;

            copy_chunk_content_to_buf(
                &chunk_content,
                buf,
                read_bytes,
                current_read_len,
                inner_position,
            )?;

            read_bytes += current_read_len;
        }
        Ok(read_bytes)
    }
}

impl<R: ReadAt> ReadAt for ZffObjectReaderLogical<R> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        self.read_at_file(buf, offset, self.active_file)
    }

    fn size(&mut self) -> std::io::Result<u64> {
        let filemetadata = self
            .files
            .get(&self.active_file)
            .ok_or(IoError::other(format!(
                "{ERROR_MISSING_FILE_NUMBER}{}",
                self.active_file
            )))?;
        Ok(filemetadata.length_of_data())
    }
}

impl<R: ReadAt> Read for ZffObjectReaderLogical<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let afp = match self.file_positions.get(&self.active_file) {
            Some(afp) => afp,
            None => {
                return Err(IoError::new(
                    IoEKind::NotFound,
                    format!("{ERROR_MISSING_FILE_NUMBER}{}", &self.active_file),
                ));
            }
        };
        let read_bytes = self.read_at(buffer, *afp)?;
        let afp = match self.file_positions.get_mut(&self.active_file) {
            Some(afp) => afp,
            None => {
                return Err(IoError::new(
                    IoEKind::NotFound,
                    format!("{ERROR_MISSING_FILE_NUMBER}{}", &self.active_file),
                ));
            }
        };
        *afp += read_bytes as u64;
        Ok(read_bytes)
    }
}

impl<R: ReadAt> Seek for ZffObjectReaderLogical<R> {
    fn seek(&mut self, seek_from: SeekFrom) -> std::result::Result<u64, std::io::Error> {
        let afp = match self.file_positions.get_mut(&self.active_file) {
            Some(afp) => afp,
            None => {
                return Err(IoError::new(
                    IoEKind::NotFound,
                    format!("{ERROR_MISSING_FILE_NUMBER}{}", &self.active_file),
                ));
            }
        };
        let filemetadata = self
            .files
            .get(&self.active_file)
            .ok_or(IoError::other(format!(
                "{ERROR_MISSING_FILE_NUMBER}{}",
                self.active_file
            )))?;
        let length_of_data = filemetadata.length_of_data();
        *afp = match seek_from {
            SeekFrom::Start(value) => value,
            SeekFrom::Current(value) => afp
                .checked_add_signed(value)
                .ok_or_else(|| std::io::Error::other(ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))?,
            SeekFrom::End(value) => length_of_data
                .checked_add_signed(value)
                .ok_or_else(|| std::io::Error::other(ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))?,
        };
        Ok(*afp)
    }
}
