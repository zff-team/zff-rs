// - STD
use std::io::{Error as IoError, ErrorKind as IoEKind, Read, Seek, SeekFrom};
use std::sync::Arc;

// - internal
use crate::prelude::*;
use crate::{
    helper::copy_chunk_content_to_buf,
    io::zffreader::{ArcZffReaderMetadata, get_chunk_data},
};

// - external
use moka::sync::Cache as MokaCache;

/// A reader which contains the appropriate metadata of a physical object
/// (e.g. the appropriate [ObjectHeader](crate::header::ObjectHeader) and [ObjectFooter](crate::footer::ObjectFooter)).
#[derive(Debug)]
pub(crate) struct ZffObjectReaderPhysical<R: ReadAt> {
    metadata: ArcZffReaderMetadata<R>,
    object_header: ObjectHeader,
    object_footer: ObjectFooterPhysical,
    reader_cache: MokaCache<u64, Arc<ChunkContent>>, //cache which holds the current chunk content (for performance purposes)
    position: u64,
}

impl<R: ReadAt> ZffObjectReaderPhysical<R> {
    /// creates a new [ZffObjectReaderPhysical] with the given metadata.
    pub fn new(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Self {
        let object_header = metadata.object_header(&object_no).unwrap().clone();
        let object_footer = match metadata.object_footer(&object_no) {
            Some(ObjectFooter::Physical(footer)) => footer.clone(),
            _ => unreachable!(), // already checked before in zffreader::initialize_unencrypted_object_reader();
        };
        Self {
            metadata,
            object_header,
            object_footer,
            reader_cache: MokaCache::builder()
                .max_capacity(DEFAULT_CHUNK_CACHE_CAPACITY)
                .build(),
            position: 0,
        }
    }

    /// Returns a reference to the [ObjectHeader](crate::header::ObjectHeader).
    pub fn object_header_ref(&self) -> &ObjectHeader {
        &self.object_header
    }

    /// Returns the appropriate [ObjectFooter](crate::footer::ObjectFooter).
    pub fn object_footer(&self) -> ObjectFooter {
        ObjectFooter::Physical(self.object_footer.clone())
    }

    /// Returns the unwrapped object footer
    pub fn object_footer_unwrapped_ref(&self) -> &ObjectFooterPhysical {
        &self.object_footer
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

impl<R: ReadAt> ReadAt for ZffObjectReaderPhysical<R> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<usize> {
        if buf.is_empty() || offset >= self.object_footer.length_of_data {
            return Ok(0);
        };

        let chunk_size = self.object_header.chunk_size;
        if chunk_size == 0 {
            return Err(IoError::new(IoEKind::InvalidData, ERROR_MALFORMED_SEGMENT));
        }

        let bytes_to_read =
            (buf.len() as u64).min(self.object_footer.length_of_data - offset) as usize;
        let mut read_bytes = 0;
        let first_chunk_number = self.object_footer.first_chunk_number;

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

    fn size(&mut self) -> std::io::Result<u64> {
        Ok(self.object_footer.length_of_data)
    }
}

impl<R: ReadAt> Read for ZffObjectReaderPhysical<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read_bytes = self.read_at(buffer, self.position)?;
        self.position += read_bytes as u64;
        Ok(read_bytes)
    }
}

impl<R: ReadAt> Seek for ZffObjectReaderPhysical<R> {
    fn seek(&mut self, seek_from: SeekFrom) -> std::result::Result<u64, std::io::Error> {
        self.position = match seek_from {
            SeekFrom::Start(value) => value,
            SeekFrom::Current(value) => self
                .position
                .checked_add_signed(value)
                .ok_or_else(|| std::io::Error::other(ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))?,
            SeekFrom::End(value) => self
                .object_footer
                .length_of_data
                .checked_add_signed(value)
                .ok_or_else(|| std::io::Error::other(ERROR_IO_NOT_SEEKABLE_NEGATIVE_POSITION))?,
        };
        Ok(self.position)
    }
}
