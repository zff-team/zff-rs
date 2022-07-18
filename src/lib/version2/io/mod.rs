// - STD
use std::io::{Read};
use std::fs::{Metadata};
use std::collections::HashMap;
use std::path::{Path};

#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;

#[cfg(target_family = "windows")]
use std::os::windows::fs::MetadataExt;

// - modules
mod zffcreator;
mod zffreader;
mod zffextender;

// - re-exports
pub use zffcreator::*;
pub use zffreader::*;
pub use zffextender::*;

// - internal
use crate::{
	Result,
	header::{FileHeader, FileType},
	ZffError,
	ZffErrorKind,
	ObjectEncoder,
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
};


#[cfg(target_family = "windows")]
use crate::{
	METADATA_EXT_DW_FILE_ATTRIBUTES
};

// - external
use time::{OffsetDateTime};

struct ObjectEncoderInformation<R: Read> {
	pub object_encoder: ObjectEncoder<R>,
	pub written_object_header: bool,
	pub unaccessable_files: Vec<String>,
}

impl<R: Read> ObjectEncoderInformation<R> {
	fn with_data(object_encoder: ObjectEncoder<R>, written_object_header: bool, unaccessable_files: Vec<String>) -> ObjectEncoderInformation<R> {
		Self {
			object_encoder,
			written_object_header,
			unaccessable_files
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
	let timestamps = get_time_from_metadata(metadata);
	let atime = timestamps.get("atime").unwrap();
	let mtime = timestamps.get("mtime").unwrap();
	let ctime = timestamps.get("ctime").unwrap();
	let btime = timestamps.get("btime").unwrap();

	let metadata_ext = get_metadata_ext(metadata);

	let file_header = FileHeader::new(
					DEFAULT_HEADER_VERSION_FILE_HEADER,
					current_file_number,
					filetype,
					filename,
					parent_file_number,
					*atime,
					*mtime,
					*ctime,
					*btime,
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