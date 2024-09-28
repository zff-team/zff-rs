// - modules
/// provides [ZffWriter](crate::io::zffwriter::ZffWriter) and some helper functions to create or extend zff containers.
pub mod zffwriter;
/// provides [ZffReader](crate::io::zffreader::ZffReader) and some helper functions to read zff containers.
pub mod zffreader;
/// provides [ZffStreamer] which implements the [Read](std::io::Read) trait to obtain a Read-Stream for a zff container.
pub mod zffstreamer;

// - STD
use std::io::{Read, copy as io_copy};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::fs::{Metadata, read_link, File, read_dir};
use std::thread::sleep;
use std::time::Duration;

#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_family = "unix")]
use std::fs::metadata;

#[cfg(target_family = "windows")]
use std::os::windows::fs::MetadataExt;

// - internal
use crate::{
    Result,
    header::{FileHeader, FileType, CompressionHeader, ObjectHeader, DeduplicationChunkMap, MetadataExtendedValue},
    footer::MainFooter,
    ZffError,
    ZffErrorKind,
    ObjectEncoder,
    CompressionAlgorithm,
    PhysicalObjectEncoder,
    LogicalObjectEncoder,
    PreparedData,
    hashing::HashType,
    constants::*,
};

// - external
use crc32fast::Hasher as CRC32Hasher;
use ed25519_dalek::SigningKey;
#[cfg(target_family = "unix")]
use time::OffsetDateTime;
#[cfg(target_family = "unix")]
use posix_acl::{PosixACL, Qualifier, ACLEntry};
#[cfg(target_family = "unix")]
use xattr::XAttrs;

#[cfg(feature = "log")]
use log::{info, warn, debug};

#[derive(Debug, Clone)]
struct ZffExtenderParameter {
	pub main_footer: MainFooter,
	pub current_segment: PathBuf,
	pub next_object_no: u64,
	pub initial_chunk_number: u64,
}

impl ZffExtenderParameter {
	fn with_data(
		main_footer: MainFooter,
		current_segment: PathBuf,
		next_object_no: u64,
		initial_chunk_number: u64,
		) -> Self {
		Self {
			main_footer,
			current_segment,
			next_object_no,
			initial_chunk_number,
		}
	}
}

/// This struct contains optional, additional parameter for the [ZffWriter](zffwriter::ZffWriter).
/// The [ZffWriter](zffwriter::ZffWriter) will use this parameter to create a new zff container.
#[derive(Default, Debug)]
pub struct ZffCreationParameters {
    /// If given, the appropriate data will be signed by the given [SigningKey].
	pub signature_key: Option<SigningKey>,
	/// If None, the container will not be segmentized. Otherwise, [ZffWriter](zffwriter::ZffWriter) ensure that no segment will be larger than this size.
	pub target_segment_size: Option<u64>,
	/// An optional description for the container
	/// (note: you can describe every object with custom descriptions by using the [DescriptionHeader](crate::header::DescriptionHeader)).
	pub description_notes: Option<String>,
	/// If set, the chunkmaps will not grow larger than the given size. Otherwise, the default size 32k will be used.
	pub chunkmap_size: Option<u64>, //default is 32k
	/// Optional [DeduplicationChunkMap] to ensure a chunk deduplication (and safe some disk space).
	pub deduplication_chunkmap: Option<DeduplicationChunkMap>,
	/// Will be used as a unique identifier, to assign each segment to the appropriate zff container.
	/// If the [ZffWriter](zffwriter::ZffWriter) will be extend an existing Zff container, this value will be ignored.
	pub unique_identifier: u64
}

#[derive(Default, Debug)]
pub(crate) struct BufferedChunk {
    pub buffer: Vec<u8>,
    pub bytes_read: u64,
    pub error_flag: bool,
}

impl BufferedChunk {
    pub fn with_chunksize(chunk_size: usize) -> BufferedChunk {
        Self {
            buffer: vec![0; chunk_size],
            bytes_read: 0,
            error_flag: false,
        }
    } 
}

// returns the buffer with the read bytes and the number of bytes which was read.
pub(crate) fn buffer_chunk<R>(
	input: &mut R,
	chunk_size: usize,
	) -> Result<BufferedChunk> 
where
	R: Read,
{
    let mut buffered_chunk = BufferedChunk::with_chunksize(chunk_size);
    let mut interrupt_retries = 0;

    while (buffered_chunk.bytes_read as usize) < chunk_size {
        let r = match input.read(&mut buffered_chunk.buffer[buffered_chunk.bytes_read as usize..]) {
        	Ok(r) => r,
        	Err(e) => match e.kind() {
                //the Error::io::ErrorKind::Interrupted guarantees 
                // that the read operation can be retried (see https://doc.rust-lang.org/std/io/trait.Read.html#tymethod.read)
        		std::io::ErrorKind::Interrupted => {
                    if interrupt_retries < DEFAULT_NUMBER_OF_RETRIES_IO_INTERRUPT {
                        #[cfg(feature = "log")]
                        warn!("Read operation was interrupted. Retry reading ({} of {}).", interrupt_retries, DEFAULT_NUMBER_OF_RETRIES_IO_INTERRUPT);
                        sleep(Duration::from_millis(DEFAULT_WAIT_TIME_IO_INTERRUPT_RETRY));
                        interrupt_retries += 1;
                        continue;
                    } else {
                        buffered_chunk.error_flag = true;
                        #[cfg(feature = "log")] {
                            warn!("The read operation was interrupted {} times.", interrupt_retries);
                            warn!("The appropriate chunk will be marked with error flag and the content will be zeroed");
                        }
                        chunk_size
                    }
                },
        		_ => return Err(ZffError::from(e)),
        	},
        };
        if r == 0 {
            break;
        }
        buffered_chunk.bytes_read += r as u64;
    }
    if buffered_chunk.bytes_read as usize != chunk_size {
        buffered_chunk.buffer = buffered_chunk.buffer[..buffered_chunk.bytes_read as usize].to_vec();
    }
    if buffered_chunk.error_flag {
        buffered_chunk.buffer = vec![0; chunk_size];
        buffered_chunk.bytes_read = chunk_size as u64;
    }

    /*let buffered_chunk.buffer = if bytes_read == chunk_size {
        buffered_chunk.buffer
    } else {
        buffered_chunk.buffer[..bytes_read].to_vec()
    };*/

    Ok(buffered_chunk)
}

/// calculates a crc32 hash for the given bytes.
pub fn calculate_crc32(buffer: &[u8]) -> u32 {
    let mut crc32_hasher = CRC32Hasher::new();
    crc32_hasher.update(buffer);
    
    crc32_hasher.finalize()
}

/// This function takes the buffered bytes and tries to compress them. 
/// 
/// If the compression rate is greater than the threshold value of the given
/// [CompressionHeader], the function returns a tuple of compressed bytes and the flag, if the bytes was compressed or not.
pub fn compress_buffer(buf: Vec<u8>, chunk_size: usize, compression_header: &CompressionHeader) -> Result<(Vec<u8>, bool)> {
    let mut compression_flag = false;
    let compression_threshold = compression_header.threshold;

    match compression_header.algorithm {
        CompressionAlgorithm::None => Ok((buf, compression_flag)),
        CompressionAlgorithm::Zstd => {
            let compression_level = compression_header.level as i32;
            let mut stream = zstd::stream::read::Encoder::new(buf.as_slice(), compression_level)?;
            let buffered_chunk = buffer_chunk(&mut stream, chunk_size * compression_header.level as usize)?;
            if (buf.len() as f32 / buffered_chunk.buffer.len() as f32) < compression_threshold {
                Ok((buf, compression_flag))
            } else {
                compression_flag = true;
                Ok((buffered_chunk.buffer, compression_flag))
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
        deduplication_map: Option<&mut DeduplicationChunkMap>) -> Result<PreparedData> {
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

    /// returns the total number of files which will be touched by the logical object encoder.
    /// will return None, if the object encoder is a physical object encoder.
    pub fn files_left(&self) -> Option<u64> {
        self.object_encoder.files_left()
    }
}


#[cfg(target_family = "unix")]
fn get_metadata_ext<P: AsRef<Path>>(path: P) -> Result<HashMap<String, MetadataExtendedValue>> {
    let metadata = std::fs::symlink_metadata(path.as_ref())?;
    let mut metadata_ext = HashMap::new();

    //dev-id
    metadata_ext.insert(METADATA_EXT_KEY_DEVID.into(), metadata.dev().into());
    // inode
    metadata_ext.insert(METADATA_EXT_KEY_INODE.into(), metadata.ino().into());
    // mode
    metadata_ext.insert(METADATA_EXT_KEY_MODE.into(), metadata.mode().into());
    // uid
    metadata_ext.insert(METADATA_EXT_KEY_UID.into(), metadata.uid().into());
    // gid
    metadata_ext.insert(METADATA_EXT_KEY_GID.into(), metadata.gid().into());

    // timestamps
    let timestamps = get_time_from_metadata(&metadata);
    let atime = timestamps.get(METADATA_ATIME).unwrap();
    let mtime = timestamps.get(METADATA_MTIME).unwrap();
    let ctime = timestamps.get(METADATA_CTIME).unwrap();
    let btime = timestamps.get(METADATA_BTIME).unwrap();

    metadata_ext.insert(METADATA_ATIME.into(), atime.into());
    metadata_ext.insert(METADATA_MTIME.into(), mtime.into());
    metadata_ext.insert(METADATA_CTIME.into(), ctime.into());
    metadata_ext.insert(METADATA_BTIME.into(), btime.into());

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
fn get_metadata_ext<P: AsRef<Path>>(path: P) -> Result<HashMap<String, MetadataExtendedValue>> {
    let metadata = std::fs::symlink_metadata(path.as_ref())?;

    let mut metadata_ext = HashMap::new();

    //dwFileAttributes
    metadata_ext.insert(METADATA_EXT_DW_FILE_ATTRIBUTES.into(), metadata.file_attributes().into());

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
fn get_xattr_metadata<P: AsRef<Path>>(xattrs: XAttrs, path: P) -> Result<HashMap<String, MetadataExtendedValue>> {
    let mut metadata_ext_map = HashMap::new();
    for ext_attr in xattrs {
        let ext_attr = ext_attr.to_string_lossy().to_string();
        // skip posix acls as we have defined the acl in other ways.
        if ext_attr.starts_with(XATTR_ATTRNAME_POSIX_ACL) || ext_attr.starts_with(XATTR_ATTRNAME_POSIX_ACL_DEFAULT) {
            continue;
        }
        let value = xattr::get(path.as_ref(), &ext_attr)?.unwrap_or_default();
        metadata_ext_map.insert(ext_attr, value.into());
    }
    Ok(metadata_ext_map)
}


#[cfg(target_family = "unix")]
pub(crate) fn get_posix_acls(acl: &PosixACL, default_acls: Option<&PosixACL>) -> HashMap<String, MetadataExtendedValue> {
    let mut metadata_ext_map = HashMap::new();
    for entry in acl.entries() {
        if let Some((key, value)) = gen_acl_key_value(false, &entry) {
            metadata_ext_map.insert(key, value.into());
        }
    };
    if let Some(default_acls) = default_acls {
        for entry in default_acls.entries() {
            if let Some((key, value)) = gen_acl_key_value(false, &entry) {
                metadata_ext_map.insert(key, value.into());
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

/// This function sets up the [ObjectEncoder] for the physical objects.
fn setup_physical_object_encoder<R: Read>(
	physical_objects: HashMap<ObjectHeader, R>,
	hash_types: &Vec<HashType>,
	signature_key_bytes: &Option<Vec<u8>>,
	chunk_number: u64,
	object_encoder: &mut Vec<ObjectEncoderInformation<R>>) -> Result<()> {
	for (object_header, stream) in physical_objects {
		let encoder = PhysicalObjectEncoder::new(
			object_header,
			stream,
			hash_types.to_owned(),
			signature_key_bytes.clone(),
			chunk_number)?;
		object_encoder.push(ObjectEncoderInformation::with_data(ObjectEncoder::Physical(Box::new(encoder)), false));
	}
	Ok(())
}

/// This function sets up the [ObjectEncoder] for the logical objects.
fn setup_logical_object_encoder<R: Read>(
    logical_objects: HashMap<ObjectHeader, Vec<PathBuf>>,
    hash_types: &Vec<HashType>,
    signature_key_bytes: &Option<Vec<u8>>,
    chunk_number: u64,
    object_encoder: &mut Vec<ObjectEncoderInformation<R>>) -> Result<()> {
    for (logical_object_header, input_files) in logical_objects {
        #[cfg(feature = "log")]
        info!("Collecting files and folders for logical object {} using following paths: {:?}",
            logical_object_header.object_number, input_files);

        let lobj = setup_logical_object(
            logical_object_header,
            input_files,
            hash_types,
            signature_key_bytes,
            chunk_number)?;
        object_encoder.push(
            ObjectEncoderInformation::with_data(
                ObjectEncoder::Logical(
                    Box::new(lobj)),
                    false));
    }
    Ok(())
}

fn setup_logical_object(
    logical_object_header: ObjectHeader,
    input_files: Vec<PathBuf>,
    hash_types: &Vec<HashType>,
    signature_key_bytes: &Option<Vec<u8>>,
    chunk_number: u64) -> Result<LogicalObjectEncoder> {

    let mut current_file_number = 0;
    let mut parent_file_number = 0;
    let mut directories_to_traversal = VecDeque::new(); // <(path, parent_file_number, current_file_number)>
    let mut files = Vec::new();
    let mut symlink_real_paths = HashMap::new();
    let mut directory_children = HashMap::<u64, Vec<u64>>::new(); //<file number of directory, Vec<filenumber of child>>
    let mut root_dir_filenumbers = Vec::new();

    let mut hardlink_map = HashMap::new();

    //files in virtual root folder
    for path in input_files {
        current_file_number += 1;

        let metadata = match check_and_get_metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };

        root_dir_filenumbers.push(current_file_number);
        if metadata.file_type().is_dir() {
            directories_to_traversal.push_back((path, parent_file_number, current_file_number));
        } else {
            if metadata.file_type().is_symlink() {
                // the error case should not reached, but if, then the target can't be read (and the file is "empty").
                match read_link(&path) {
                    Ok(symlink_real) => symlink_real_paths.insert(current_file_number, symlink_real),
                    Err(_) => symlink_real_paths.insert(current_file_number, PathBuf::from("")),
                };
            }
            let mut file_header = match get_file_header(&path, current_file_number, parent_file_number) {
                Ok(file_header) => file_header,
                Err(_) => continue,
            };

            //test if file is readable and exists.
            check_file_accessibility(&path, &mut file_header);

            // add the file to the hardlink map
            add_to_hardlink_map(&mut hardlink_map, &metadata, current_file_number);

            files.push((path.clone(), file_header));
        }
    }

    // - traverse files in subfolders
    while let Some((current_dir, dir_parent_file_number, dir_current_file_number)) = directories_to_traversal.pop_front() {
        parent_file_number = dir_current_file_number;
        // creates an iterator to iterate over all files in the appropriate directory
        // if the directory can not be read e.g. due a permission error, the metadata
        // of the directory will be stored in the container as an empty directory.
        let element_iterator = match create_iterator(
            current_dir,
            &mut hardlink_map,
            dir_current_file_number,
            dir_parent_file_number,
            &mut directory_children,
            &mut files,
            ) {
            Ok(iterator) => iterator,
            Err(_) => continue,
        };

        // handle files in current folder
        for inner_element in element_iterator {
            #[cfg_attr(not(feature = "log"), allow(unused_variables))]
            let inner_element = match inner_element {
                Ok(element) => element,
                Err(e) => {
                    // not sure if this can be reached, as we checked a few things before.
                    #[cfg(feature = "log")]
                    debug!("Error while trying to unwrap the inner element of the element iterator: {e}.");
                    continue;
                }
            };

            let metadata = match check_and_get_metadata(inner_element.path()) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };

            current_file_number += 1;

            if metadata.file_type().is_dir() {
                directories_to_traversal.push_back((inner_element.path(), parent_file_number, current_file_number));
            } else {
                if let Some(files_vec) = directory_children.get_mut(&parent_file_number) {
                    files_vec.push(current_file_number);
                } else {
                    directory_children.insert(parent_file_number, Vec::new());
                    directory_children.get_mut(&parent_file_number).unwrap().push(current_file_number);
                };

                match read_link(inner_element.path()) {
                    Ok(symlink_real) => symlink_real_paths.insert(current_file_number, symlink_real),
                    Err(_) => symlink_real_paths.insert(current_file_number, PathBuf::from("")),
                };
                let path = inner_element.path().clone();
                let mut file_header = match get_file_header(&path, current_file_number, parent_file_number) {
                    Ok(file_header) => file_header,
                    Err(_) => continue,
                };

                //test if file is readable and exists.
                check_file_accessibility(inner_element.path(), &mut file_header);
                
                add_to_hardlink_map(&mut hardlink_map, &metadata, current_file_number);

                files.push((inner_element.path().clone(), file_header));
            }
        }
    }

    #[cfg(target_family = "unix")]
    let hardlink_map = transform_hardlink_map(hardlink_map, &mut files)?;

    #[cfg(target_family = "windows")]
    let hardlink_map = HashMap::new();

    let log_obj = LogicalObjectEncoder::new(
        logical_object_header,
        files,
        root_dir_filenumbers,
        hash_types.to_owned(),
        signature_key_bytes.clone(),
        symlink_real_paths,
        hardlink_map,
        directory_children,
        chunk_number)?;
    Ok(log_obj)
}


fn check_and_get_metadata<P: AsRef<Path>>(path: P) -> Result<Metadata> {
	match std::fs::symlink_metadata(path.as_ref()) {
		Ok(metadata) => Ok(metadata),
		Err(e) => {
			#[cfg(feature = "log")]
			warn!("The metadata of the file {:?} can't be read. This file will be completly ignored.", path.as_ref().display());
			#[cfg(feature = "log")]
			debug!("{e}");
			Err(e.into())
		},
	}
}

#[cfg_attr(not(feature = "log"), allow(unused_variables))]
fn check_file_accessibility<P: AsRef<Path>>(path: P, file_header: &mut FileHeader) {
	match File::open(path.as_ref()) {
		Ok(_) => (),
		Err(e) => {
			#[cfg(feature = "log")]
			warn!("The content of the file {} can't be read, due the following error: {e}.\
				The file will be stored as an empty file.", path.as_ref().display());
			// set the "ua" tag and the full path in file metadata.
			file_header.metadata_ext.insert(METADATA_EXT_KEY_UNACCESSABLE_FILE.to_string(), path.as_ref().to_string_lossy().to_string().into());
		},
	};
}

fn create_iterator<C: AsRef<Path>>(
	current_dir: C,
	hardlink_map: &mut HashMap<u64, HashMap<u64, u64>>,
	dir_current_file_number: u64,
	dir_parent_file_number: u64,
	directory_children: &mut HashMap::<u64, Vec<u64>>,
	files: &mut Vec<(PathBuf, FileHeader)>,
	) -> Result<std::fs::ReadDir> {
    #[cfg_attr(not(feature = "log"), allow(unused_variables))]
	let metadata = match std::fs::symlink_metadata(current_dir.as_ref()) {
		Ok(metadata) => metadata,
		Err(e) => {
			#[cfg(feature = "log")]
			warn!("The metadata of the file {} can't be read. This file will be completly ignored.", &current_dir.as_ref().display());
			#[cfg(feature = "log")]
			debug!("{e}");
			return Err(e.into());
		},
	};

	if let Some(files_vec) = directory_children.get_mut(&dir_parent_file_number) {
		files_vec.push(dir_current_file_number);
	} else {
		directory_children.insert(dir_parent_file_number, Vec::new());
		directory_children.get_mut(&dir_parent_file_number).unwrap().push(dir_current_file_number);
	};
	let mut file_header = match get_file_header(current_dir.as_ref(), dir_current_file_number, dir_parent_file_number) {
		Ok(file_header) => file_header,
		Err(e) => return Err(e),
	};

	let iterator = match read_dir(current_dir.as_ref()) {
		Ok(iterator) => iterator,
		Err(e) => {
			// if the directory is not readable, we should continue but read the metadata of the directory.
			#[cfg(feature = "log")]
			warn!("The content of the file {} can't be read, due the following error: {e}.\
				The file will be stored as an empty file.", &current_dir.as_ref().display());
			file_header.metadata_ext.insert(METADATA_EXT_KEY_UNACCESSABLE_FILE.to_string(), current_dir.as_ref().to_string_lossy().to_string().into());
			files.push((current_dir.as_ref().to_path_buf(), file_header));
			return Err(e.into());
		}
	};
	add_to_hardlink_map(hardlink_map, &metadata, dir_current_file_number);
	files.push((current_dir.as_ref().to_path_buf(), file_header));
	
	Ok(iterator)
}

#[cfg(target_family = "unix")]
fn transform_hardlink_map(hardlink_map: HashMap<u64, HashMap<u64, u64>>, files: &mut Vec<(PathBuf, FileHeader)>) -> Result<HashMap<u64, u64>> {
	let mut inner_hardlink_map = HashMap::new();
	for (path, file_header) in files {
		let metadata = metadata(path)?;
		if let Some(inner_map) = hardlink_map.get(&metadata.dev()) {
    		if let Some(fno) = inner_map.get(&metadata.ino()) {
				if *fno != file_header.file_number {
					file_header.transform_to_hardlink();
					inner_hardlink_map.insert(file_header.file_number, *fno);
				};
	    	}
     	}
	}
    Ok(inner_hardlink_map)
}

fn prepare_object_header<R: Read>(
    physical_objects: &mut HashMap<ObjectHeader, R>, // <ObjectHeader, input_data stream>
	logical_objects: &mut HashMap<ObjectHeader, Vec<PathBuf>>, //<ObjectHeader, input_files>,
    extender_parameter: &Option<ZffExtenderParameter>
) -> Result<()> {
    let mut next_object_number = match &extender_parameter {
        None => INITIAL_OBJECT_NUMBER,
        Some(params) => params.next_object_no,
    };

    let mut modify_map_phy = HashMap::new();
    // check if all necessary stuff is available in object header and modify them (if needed)
    for (mut header, reader) in physical_objects.drain() {
        // check if all EncryptionHeader are contain a decrypted encryption key.
        check_encryption_key_in_header(&header)?;
        // modifies the appropriate object numbers to the right values.
        header.object_number = next_object_number;
        next_object_number += 1;

        modify_map_phy.insert(header, reader);
    }
    physical_objects.extend(modify_map_phy);

    let mut modify_map_log = HashMap::new();
    for (mut header, input_files) in logical_objects.drain() {
        //check if all EncryptionHeader are contain a decrypted encryption key.
        check_encryption_key_in_header(&header)?;        
        // modifies the appropriate object numbers to the right values.
        header.object_number = next_object_number;
        next_object_number += 1;
        
        modify_map_log.insert(header, input_files);
    }
    logical_objects.extend(modify_map_log);

    Ok(())
}

fn check_encryption_key_in_header(object_header: &ObjectHeader) -> Result<()> {
    if let Some(encryption_header) = &object_header.encryption_header {
        if encryption_header.get_encryption_key_ref().is_none() {
            return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, object_header.object_number.to_string()))
        };
    }
    Ok(())
}