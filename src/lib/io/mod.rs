// - modules
/// provides [ZffWriter](crate::io::zffwriter::ZffWriter) and some helper functions to create or extend zff containers.
pub mod zffwriter;
/// provides [ZffReader](crate::io::zffreader::ZffReader) and some helper functions to read zff containers.
pub mod zffreader;
/// TODO
pub mod zffstreamer;

// - STD
use std::io::{Read, copy as io_copy};
use std::collections::HashMap;
use std::path::Path;
use std::fs::Metadata;

#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;

#[cfg(target_family = "windows")]
use std::os::windows::fs::MetadataExt;

// - internal
use crate::{
    Result,
    header::{FileHeader, FileType, CompressionHeader, ObjectHeader, DeduplicationChunkMap},
    ZffError,
    ZffErrorKind,
    ObjectEncoder,
    CompressionAlgorithm,
    constants::*,
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
use crate::METADATA_EXT_DW_FILE_ATTRIBUTES;

#[cfg(feature = "log")]
use log::warn;

// - external
use crc32fast::Hasher as CRC32Hasher;
#[cfg(target_family = "unix")]
use time::OffsetDateTime;
#[cfg(target_family = "unix")]
use posix_acl::{PosixACL, Qualifier, ACLEntry};
#[cfg(target_family = "unix")]
use xattr::XAttrs;
#[cfg(target_family = "unix")]
use base64::{Engine, engine::general_purpose::STANDARD as base64engine};

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

    /// returns a reference of the appropriate [ObjectHeader].
    fn get_obj_header(&mut self) -> &ObjectHeader {
        match &self.object_encoder {
            ObjectEncoder::Physical(obj) => obj.object_header(),
            ObjectEncoder::Logical(obj) => obj.object_header(),
        }
    }

    /// returns the appropriate encoded [ObjectHeader].
    fn get_encoded_header(&mut self) -> Vec<u8> {
        match self.object_encoder {
            ObjectEncoder::Physical(ref mut obj) => obj.get_encoded_header(),
            ObjectEncoder::Logical(ref mut obj) => obj.get_encoded_header(),
        }
    }

    /// returns the appropriate object footer.
    pub fn get_encoded_footer(&mut self) -> Result<Vec<u8>> {
        match self.object_encoder {
            ObjectEncoder::Physical(ref mut obj) => obj.get_encoded_footer(),
            ObjectEncoder::Logical(ref mut obj) => obj.get_encoded_footer(),
        }
    }

    /// returns the appropriate object number.
    fn obj_number(&self) -> u64 {
        match &self.object_encoder {
            ObjectEncoder::Physical(obj) => obj.obj_number(),
            ObjectEncoder::Logical(obj) => obj.obj_number(),
        }
    }

    /// returns the next data.
    fn get_next_data(
        &mut self, 
        current_offset: u64, 
        current_segment_no: u64,
        deduplication_map: Option<&mut DeduplicationChunkMap>) -> Result<Vec<u8>> {
        match self.object_encoder {
            ObjectEncoder::Physical(ref mut obj) => obj.get_next_chunk(deduplication_map),
            ObjectEncoder::Logical(ref mut obj) => obj.get_next_data(current_offset, current_segment_no, deduplication_map),
        }
    }

    /// returns the current chunk number.
    fn current_chunk_number(&self) -> u64 {
        match &self.object_encoder {
            ObjectEncoder::Physical(obj) => obj.current_chunk_number(),
            ObjectEncoder::Logical(obj) => obj.current_chunk_number(),
        }
    }
}


#[cfg(target_family = "unix")]
fn get_metadata_ext<P: AsRef<Path>>(path: P) -> Result<HashMap<String, String>> {
    let metadata = std::fs::symlink_metadata(path.as_ref())?;
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
    let timestamps = get_time_from_metadata(&metadata);
    let atime = timestamps.get(METADATA_ATIME).unwrap();
    let mtime = timestamps.get(METADATA_MTIME).unwrap();
    let ctime = timestamps.get(METADATA_CTIME).unwrap();
    let btime = timestamps.get(METADATA_BTIME).unwrap();

    metadata_ext.insert(METADATA_ATIME.into(), atime.to_string());
    metadata_ext.insert(METADATA_MTIME.into(), mtime.to_string());
    metadata_ext.insert(METADATA_CTIME.into(), ctime.to_string());
    metadata_ext.insert(METADATA_BTIME.into(), btime.to_string());

    // check acls on unix systems
    #[cfg(target_family = "unix")]
    if let Ok(acl) = PosixACL::read_acl(path.as_ref()) {
        metadata_ext.extend(get_posix_acls(&acl, PosixACL::read_default_acl(path.as_ref()).ok().as_ref()));
    }

    // check extended attributes on unix systems
    #[cfg(target_family = "unix")]
    if let Ok(xattrs) = xattr::list(path.as_ref()) {
        metadata_ext.extend(get_xattr_metadata(xattrs, path.as_ref())?);
    }

    Ok(metadata_ext)
}

#[cfg(target_os = "windows")]
fn get_metadata_ext<P: AsRef<Path>>(path: P) -> Result<HashMap<String, String>> {
    let metadata = std::fs::symlink_metadata(path.as_ref())?;

    let mut metadata_ext = HashMap::new();

    //dwFileAttributes
    metadata_ext.insert(METADATA_EXT_DW_FILE_ATTRIBUTES.into(), metadata.file_attributes().to_string());

    Ok(metadata_ext)
}

#[cfg(target_family = "unix")]
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

fn get_file_header(path: &Path, current_file_number: u64, parent_file_number: u64) -> Result<FileHeader> {
    let metadata = std::fs::symlink_metadata(path)?;

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

    let metadata_ext = get_metadata_ext(path);

    let file_header = FileHeader::new(
                    current_file_number,
                    filetype,
                    filename,
                    parent_file_number,
                    metadata_ext?);
    Ok(file_header)
}

#[cfg(target_family = "unix")]
fn get_xattr_metadata<P: AsRef<Path>>(xattrs: XAttrs, path: P) -> Result<HashMap<String, String>> {
    let mut metadata_ext_map = HashMap::new();
    for ext_attr in xattrs {
        let ext_attr = ext_attr.to_string_lossy().to_string();
        // skip posix acls as we have defined the acl in other ways.
        if ext_attr.starts_with(XATTR_ATTRNAME_POSIX_ACL) {
            continue;
        }
        let value = match xattr::get(path.as_ref(), &ext_attr)? {
            Some(value) => base64engine.encode(value),
            None => String::new(),
        };
        metadata_ext_map.insert(ext_attr, value);
    }
    Ok(metadata_ext_map)
}


#[cfg(target_family = "unix")]
pub(crate) fn get_posix_acls(acl: &PosixACL, default_acls: Option<&PosixACL>) -> HashMap<String, String> {
    let mut metadata_ext_map = HashMap::new();
    for entry in acl.entries() {
        if let Some((key, value)) = gen_acl_key_value(false, &entry) {
            metadata_ext_map.insert(key, value);
        }
    };
    if let Some(default_acls) = default_acls {
        for entry in default_acls.entries() {
            if let Some((key, value)) = gen_acl_key_value(false, &entry) {
                metadata_ext_map.insert(key, value);
            }
        };
    }
    metadata_ext_map
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

/// returns ...
/// ... None, if there is no other hardlink available to this file or if there is another hardlink available to this file, but this is the first of the hardlinked files, you've read.
/// ... Some(filenumber), if there is another hardlink available and already was read.
/// # Panic
/// This function panics, if the metadata was generated by using DirEntry::metadata().
#[cfg(target_family = "windows")]
fn add_to_hardlink_map(hardlink_map: &mut HashMap<u64, HashMap<u64, u64>>, metadata: &Metadata, filenumber: u64) -> Option<u64> {
    let file_index = metadata.file_index().unwrap();
    let volume_serial_number = metadata.volume_serial_number().unwrap() as u64;
    match hardlink_map.get_mut(&volume_serial_number) {
        Some(inner_map) => match inner_map.get_mut(&file_index) {
            Some(fno) => Some(*fno),
            None => {
                inner_map.insert(file_index, filenumber);
                None
            },
        },
        None => {
            hardlink_map.insert(volume_serial_number, HashMap::new());
            hardlink_map.get_mut(&volume_serial_number).unwrap().insert(file_index, filenumber);
            None
        },
    }
}

pub(crate) fn check_same_byte(vec: &[u8]) -> bool {
    if let Some(&first) = vec.first() {
        for &byte in vec.iter().skip(1) {
            if byte != first {
                return false;
            }
        }
        true
    } else {
        true // Empty vector is considered to have the same byte on every position
    }
}

#[cfg(target_family = "unix")]
fn gen_acl_key_value(default: bool, entry: &ACLEntry) -> Option<(String, String)> {
    let key = match entry.qual {
        Qualifier::User(uid) => gen_acl_key_uid(default, uid),
        Qualifier::Group(gid) => gen_acl_key_gid(default, gid),
        Qualifier::Mask => gen_acl_mask(default),
        _ => return None, // ignoring UserObj, GroupObj and Other while this is always figured by the "mode" key
    };
    Some((key, entry.perm.to_string()))
}

#[cfg(target_family = "unix")]
fn gen_acl_key_uid(default: bool, uid: u32) -> String {
    let start = if default {
        ACL_PREFIX
    } else {
        ACL_DEFAULT_PREFIX
    };
    format!("{start}:user:{uid}")
}

#[cfg(target_family = "unix")]
fn gen_acl_key_gid(default: bool, gid: u32) -> String {
    let start = if default {
        ACL_PREFIX
    } else {
        ACL_DEFAULT_PREFIX
    };
    format!("{start}:group:{gid}")
}

#[cfg(target_family = "unix")]
fn gen_acl_mask(default: bool) -> String {
    let start = if default {
        ACL_PREFIX
    } else {
        ACL_DEFAULT_PREFIX
    };
    format!("{start}:mask")
}