// - modules
pub mod zffwriter;

// - STD
use std::io::{Read, copy as io_copy};
use std::fs::{Metadata};
use std::collections::HashMap;
use std::path::{Path};

#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;

#[cfg(target_family = "windows")]
use std::os::windows::fs::MetadataExt;

// - internal
use crate::{
    Result,
    header::{FileHeader, FileType, CompressionHeader},
    ZffError,
    ZffErrorKind,
    ObjectEncoder,
    CompressionAlgorithm
};

use crate::{
    DEFAULT_HEADER_VERSION_FILE_HEADER,
};

#[cfg(target_family = "unix")]
use crate::{
    METADATA_EXT_KEY_GID,
    METADATA_EXT_KEY_UID,
    METADATA_EXT_KEY_MODE,
    METADATA_EXT_KEY_DEVID,
    METADATA_EXT_KEY_INODE,
    METADATA_ATIME,
    METADATA_MTIME,
    METADATA_CTIME,
    METADATA_BTIME,
};


#[cfg(target_family = "windows")]
use crate::{
    METADATA_EXT_DW_FILE_ATTRIBUTES
};

// - external
use time::{OffsetDateTime};
use crc32fast::{Hasher as CRC32Hasher};

// returns the buffer with the read bytes and the number of bytes which was read.
pub(crate) fn buffer_chunk<R>(
	input: &mut R,
	chunk_size: usize,
	) -> Result<(Vec<u8>, u64)> 
where
	R: Read
{
	let mut buf = vec![0u8; chunk_size];
    let mut bytes_read = 0;

    while bytes_read < chunk_size {
        let r = match input.read(&mut buf[bytes_read..]) {
        	Ok(r) => r,
        	Err(e) => match e.kind() {
        		std::io::ErrorKind::Interrupted => return Err(ZffError::new(ZffErrorKind::InterruptedInputStream, "")),
        		_ => return Err(ZffError::from(e)),
        	},
        };
        if r == 0 {
            break;
        }
        bytes_read += r;
    }

    let buf = if bytes_read == chunk_size {
        buf
    } else {
        buf[..bytes_read].to_vec()
    };
    Ok((buf, bytes_read as u64))
}

/// calculates a crc32 hash for the given bytes.
pub fn calculate_crc32(buffer: &[u8]) -> u32 {
    let mut crc32_hasher = CRC32Hasher::new();
    crc32_hasher.update(buffer);
    
    crc32_hasher.finalize()
}

/// This function takes the buffered bytes and tries to compress them. If the compression rate is greater than the threshold value of the given
/// [CompressionHeader], the function returns a tuple of compressed bytes and the flag, if the bytes was compressed or not.
pub fn compress_buffer(buf: Vec<u8>, chunk_size: usize, compression_header: &CompressionHeader) -> Result<(Vec<u8>, bool)> {
    let mut compression_flag = false;
    let compression_threshold = compression_header.threshold();

    match compression_header.algorithm() {
        CompressionAlgorithm::None => Ok((buf, compression_flag)),
        CompressionAlgorithm::Zstd => {
            let compression_level = *compression_header.level() as i32;
            let mut stream = zstd::stream::read::Encoder::new(buf.as_slice(), compression_level)?;
            let (compressed_data, _) = buffer_chunk(&mut stream, chunk_size * *compression_header.level() as usize)?;
            if (buf.len() as f32 / compressed_data.len() as f32) < compression_threshold {
                Ok((buf, compression_flag))
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
                Ok((buf, compression_flag))
            } else {
                compression_flag = true;
                Ok((compressed_data, compression_flag))
            }
        }
    }
}

struct ObjectEncoderInformation<R: Read> {
    pub object_encoder: ObjectEncoder<R>,
    pub written_object_header: bool,
}

impl<R: Read> ObjectEncoderInformation<R> {
    fn with_data(object_encoder: ObjectEncoder<R>, written_object_header: bool) -> ObjectEncoderInformation<R> {
        Self {
            object_encoder,
            written_object_header,
        }
    }
}


//TODO: target_os = "macos"
#[cfg(target_os = "linux")]
fn get_metadata_ext(metadata: &Metadata) -> HashMap<String, String> {
    let mut metadata_ext = HashMap::new();

    //dev-id
    metadata_ext.insert(METADATA_EXT_KEY_DEVID.into(), metadata.dev().to_string());
    // inode
    metadata_ext.insert(METADATA_EXT_KEY_INODE.into(), metadata.ino().to_string());
    // mode
    metadata_ext.insert(METADATA_EXT_KEY_MODE.into(), metadata.mode().to_string());
    // uid
    metadata_ext.insert(METADATA_EXT_KEY_UID.into(), metadata.uid().to_string());
    // gid
    metadata_ext.insert(METADATA_EXT_KEY_GID.into(), metadata.gid().to_string());

    // timestamps
    let timestamps = get_time_from_metadata(metadata);
    let atime = timestamps.get("atime").unwrap();
    let mtime = timestamps.get("mtime").unwrap();
    let ctime = timestamps.get("ctime").unwrap();
    let btime = timestamps.get("btime").unwrap();

    metadata_ext.insert(METADATA_ATIME.into(), atime.to_string());
    metadata_ext.insert(METADATA_MTIME.into(), mtime.to_string());
    metadata_ext.insert(METADATA_CTIME.into(), ctime.to_string());
    metadata_ext.insert(METADATA_BTIME.into(), btime.to_string());

    metadata_ext
}

#[cfg(target_os = "windows")]
fn get_metadata_ext(metadata: &Metadata) -> HashMap<String, String> {
    let mut metadata_ext = HashMap::new();

    //dwFileAttributes
    metadata_ext.insert(METADATA_EXT_DW_FILE_ATTRIBUTES.into(), metadata.file_attributes().to_string());

    metadata_ext
}

fn get_time_from_metadata(metadata: &Metadata) -> HashMap<&str, u64> {
    let mut timestamps = HashMap::new();

    let atime = match metadata.accessed() {
        Ok(atime) => OffsetDateTime::from(atime).unix_timestamp() as u64,
        Err(_) => 0
    };
    let mtime = match metadata.modified() {
        Ok(mtime) => OffsetDateTime::from(mtime).unix_timestamp() as u64,
        Err(_) => 0
    };
    #[cfg(target_family = "windows")]
    let ctime = match metadata.modified() {
        Ok(ctime) => OffsetDateTime::from(ctime).unix_timestamp() as u64,
        Err(_) => 0
    };
    #[cfg(target_family = "unix")]
    let ctime = metadata.ctime() as u64;

    let btime = match metadata.created() {
        Ok(btime) => OffsetDateTime::from(btime).unix_timestamp() as u64,
        Err(_) => 0
    };

    timestamps.insert("atime", atime);
    timestamps.insert("mtime", mtime);
    timestamps.insert("ctime", ctime);
    timestamps.insert("btime", btime);

    timestamps
}

fn get_file_header(metadata: &Metadata, path: &Path, current_file_number: u64, parent_file_number: u64) -> Result<FileHeader> {
    let filetype = if metadata.file_type().is_dir() {
        FileType::Directory
    } else if metadata.file_type().is_file() {
        FileType::File
    } else if metadata.file_type().is_symlink() {
        FileType::Symlink
    } else {
        return Err(ZffError::new(ZffErrorKind::UnknownFileType, ""));
    };

    let filename = match path.file_name() {
        Some(filename) => filename.to_string_lossy(),
        None => path.to_string_lossy(),
    };

    let metadata_ext = get_metadata_ext(metadata);

    let file_header = FileHeader::new(
                    DEFAULT_HEADER_VERSION_FILE_HEADER,
                    current_file_number,
                    filetype,
                    filename,
                    parent_file_number,
                    metadata_ext);
    Ok(file_header)
}

// returns ...
// ... None, if there is no other hardlink available to this file or if there is another hardlink available to this file, but this is the first of the hardlinked files, you've read.
// ... Some(filenumber), if there is another hardlink available and already was read.
#[cfg(target_family = "unix")]
fn add_to_hardlink_map(hardlink_map: &mut HashMap<u64, HashMap<u64, u64>>, metadata: &Metadata, filenumber: u64) -> Option<u64> {
    if metadata.nlink() > 1 {
        match hardlink_map.get_mut(&metadata.dev()) {
            Some(inner_map) => match inner_map.get_mut(&metadata.ino()) {
                Some(fno) => return Some(*fno),
                None => {
                    inner_map.insert(metadata.ino(), filenumber);
                    return None
                },
            },
            None => {
                hardlink_map.insert(metadata.dev(), HashMap::new());
                hardlink_map.get_mut(&metadata.dev()).unwrap().insert(metadata.ino(), filenumber);
                return None;
            },
        }
    }
    None
}