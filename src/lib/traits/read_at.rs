//! Module for random access reading functionality.
//!
//! This module provides traits and utilities for reading data at arbitrary offsets,
//! which is essential for working with zff container structures.
//!
//! # Traits
//!
//! - [`ReadAt`]: Trait for types that support reading at arbitrary offsets
//! - [`ReadAtFile`]: Trait for types that support reading file data at arbitrary offsets
//!
//! # Types
//!
//! - [`ReadAtCursor`]: A cursor implementation that wraps a `ReadAt` type with a position

// - STD
use std::io::{Error, ErrorKind, Read, Result, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::FileExt;
#[cfg(windows)]
use std::os::windows::fs::FileExt;

// - internal
use crate::constants::{DEFAULT_READ_BUFFER_SIZE, SMALL_BUFFER_SIZE};

pub(crate) struct ReadAtCursor<'a, R: ReadAt + ?Sized> {
    data: &'a R,
    position: u64,
}

impl<'a, R: ReadAt + ?Sized> ReadAtCursor<'a, R> {
    pub fn new(data: &'a R, offset: u64) -> Self {
        Self {
            data,
            position: offset,
        }
    }
}

impl<R: ReadAt + ?Sized> Read for ReadAtCursor<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.data.read_at(buf, self.position)?;
        self.position += bytes_read as u64;
        Ok(bytes_read)
    }
}

/// Trait for types that support reading at arbitrary offsets.
///
/// This trait is used by the zff reader implementation.
/// Internally, it uses the appropriate os-specific FileExt-traits
/// if using with std::fs::File (mostly used).
/// But it is also available for std::io::Readers (if using with std::sync::Mutex).
///
/// # Example
/// ```no_run
/// use zff::ReadAt;
/// use std::fs::File;
///
/// // Open a file that implements ReadAt
/// let file = File::open("test.zff").unwrap();
/// let mut buf = [0u8; 1024];
/// // Read 1024 bytes starting at offset 0
/// let bytes_read = file.read_at(&mut buf, 0).unwrap();
/// ```
pub trait ReadAt {
    /// Fills the buffer at the appropriate offset.
    ///
    /// # Example
    /// ```no_run
    /// use zff::ReadAt;
    /// use std::fs::File;
    ///
    /// let file = File::open("test.zff").unwrap();
    /// let mut buf = vec![0u8; 100];
    /// let bytes_read = file.read_at(&mut buf, 1000).unwrap();
    /// ```
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize>;

    /// Equivalent to read_exact_at fn in FileExt, but also usable for `Mutex<R>` implementation.
    ///
    /// # Example
    /// ```no_run
    /// use zff::ReadAt;
    /// use std::fs::File;
    ///
    /// let file = File::open("test.zff").unwrap();
    /// let mut buf = vec![0u8; 100];
    /// file.read_exact_at(&mut buf, 1000).unwrap();
    /// // buf now contains exactly 100 bytes from offset 1000
    /// ```
    fn read_exact_at(&self, mut buf: &mut [u8], mut offset: u64) -> Result<()> {
        while !buf.is_empty() {
            match self.read_at(buf, offset) {
                Ok(0) => return Err(Error::new(ErrorKind::UnexpectedEof, "early eof")),
                Ok(n) => {
                    buf = &mut buf[n..];
                    offset += n as u64;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Same as read_to_end, but starts at given offset.
    ///
    /// # Example
    /// ```no_run
    /// use zff::ReadAt;
    /// use std::fs::File;
    ///
    /// let file = File::open("test.zff").unwrap();
    /// let mut buf = Vec::new();
    /// // Read all data starting from offset 1000 to the end of file
    /// let bytes_read = file.read_at_to_end(&mut buf, 1000).unwrap();
    /// ```
    fn read_at_to_end(&self, buf: &mut Vec<u8>, mut offset: u64) -> Result<usize> {
        let start_offset = offset;
        let mut chunk = [0u8; SMALL_BUFFER_SIZE];
        loop {
            match self.read_at(&mut chunk, offset) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    offset += n as u64;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        Ok((offset - start_offset) as usize)
    }

    /// Returns the total size in bytes (=max offset).
    ///
    /// # Example
    /// ```no_run
    /// use zff::ReadAt;
    /// use std::fs::File;
    ///
    /// let file = File::open("test.zff").unwrap();
    /// let mut file_clone = file.try_clone().unwrap();
    /// let size = file_clone.size().unwrap();
    /// ```
    fn size(&mut self) -> Result<u64>;
}

#[cfg(unix)]
impl ReadAt for std::fs::File {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        FileExt::read_at(self, buf, offset)
    }

    fn size(&mut self) -> Result<u64> {
        let position = self.stream_position()?;
        let end_pos = self.seek(SeekFrom::End(0))?;
        self.seek(SeekFrom::Start(position))?;
        Ok(end_pos)
    }
}

#[cfg(windows)]
impl ReadAt for std::fs::File {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        FileExt::seek_read(self, buf, offset)
    }

    fn size(&mut self) -> Result<u64> {
        let position = self.stream_position()?;
        let end_pos = self.seek(SeekFrom::End(0))?;
        self.seek(SeekFrom::Start(position))?;
        Ok(end_pos)
    }
}

impl<R: Read + Seek> ReadAt for std::sync::Mutex<R> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        let mut inner = match self.lock() {
            Ok(value) => value,
            Err(e) => return Err(Error::other(e.to_string())),
        };
        inner.seek(SeekFrom::Start(offset))?;
        inner.read(buf)
    }

    fn size(&mut self) -> Result<u64> {
        let inner = match self.get_mut() {
            Ok(value) => value,
            Err(e) => return Err(Error::other(e.to_string())),
        };
        let position = inner.stream_position()?;
        let end_pos = inner.seek(SeekFrom::End(0))?;
        inner.seek(SeekFrom::Start(position))?;
        Ok(end_pos)
    }
}

/// Trait similar to ReadAt but for underlying files.
///
/// This trait is used for reading specific files within objects.
pub trait ReadAtFile {
    /// Fills the buffer at the appropriate offset.
    fn read_at_file(&self, buf: &mut [u8], offset: u64, file_no: u64) -> std::io::Result<usize>;

    /// Same as read_to_end, but starts at given offset.
    fn read_at_file_to_end(
        &self,
        buf: &mut Vec<u8>,
        mut offset: u64,
        file_no: u64,
    ) -> std::io::Result<usize> {
        let start_offset = offset;
        let mut chunk = [0u8; DEFAULT_READ_BUFFER_SIZE];
        loop {
            match self.read_at_file(&mut chunk, offset, file_no) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    offset += n as u64;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }

        Ok((offset - start_offset) as usize)
    }
}
