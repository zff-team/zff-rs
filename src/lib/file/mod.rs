// - internal
use crate::prelude::*;

// - external
#[cfg(feature = "serde")]
use serde::{Serialize};

// - modules
mod file_encoder;
mod virtual_file_encoder;

// - re-exports
pub use file_encoder::*;
pub use virtual_file_encoder::*;

/// Metadata extracted from a [VirtualFileFooter].
///
/// This type is the reader-facing representation of a virtual file footer and
/// stores the footer information without the virtual file number, which is
/// already available in the appropriate [FileHeader].
#[derive(Debug,Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct VirtualFileFooterMetadata {
	/// The hash information for the virtual file data.
	pub hash_header: HashHeader,
	/// The logical length of the represented file data in bytes.
    pub length_of_data: u64,
	/// The virtual file specific content description.
    pub vfc: VirtualFileContent,
}

impl VirtualFileFooterMetadata {
	/// Creates a new [VirtualFileFooterMetadata] from the given data.
	pub fn new(hash_header: HashHeader, length_of_data: u64, vfc: VirtualFileContent) -> Self {
		Self {
			hash_header,
			length_of_data,
			vfc
		}
	}
}

impl From<VirtualFileFooter> for VirtualFileFooterMetadata {
	fn from(vff: VirtualFileFooter) -> Self {
		Self {
			hash_header: vff.hash_header,
			length_of_data: vff.length_of_data,
			vfc: vff.vffc.into()
		}
	}
}


/// Describes how a virtual file is represented inside a
/// [VirtualFileFooterMetadata].
///
/// Depending on the virtual file type, the content either references a virtual
/// file map for regular file data or stores the metadata needed to represent
/// directories, links, and special files.
#[derive(Debug,Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum VirtualFileContent {
	/// Contains the resolved [VirtualFileMap] for a regular virtual file.
	FileMap(VirtualFileMap),
	/// Contains the (segment_no, offset) tuple pointing to the corresponding
	/// serialized [VirtualFileMap].
	FileMapPosition(u64, u64),
	/// Contains the file numbers of all direct children of the directory.
	Directory(Vec<u64>),
	/// Contains the symlink target path.
	Symlink(PlatformString),
	/// Contains the file number of the referenced hardlink target.
	Hardlink(u64),
	/// Contains the merged `rdev` identifier and the corresponding special file
	/// type.
	SpecialFile(u64, SpecialFileType)
}

impl From<VirtualFileFooterContent> for VirtualFileContent {
	fn from(value: VirtualFileFooterContent) -> Self {
		match value {
			VirtualFileFooterContent::Directory(vec) => VirtualFileContent::Directory(vec),
			VirtualFileFooterContent::Symlink(link) => VirtualFileContent::Symlink(link),
			VirtualFileFooterContent::Hardlink(link) => VirtualFileContent::Hardlink(link),
			VirtualFileFooterContent::SpecialFile(rdev_id, stype) => VirtualFileContent::SpecialFile(rdev_id, stype),
			VirtualFileFooterContent::FileMap(seg, off) => VirtualFileContent::FileMapPosition(seg, off),
		}
	}
}

/// References the location of a serialized [VirtualFileMap] inside a zff
/// segment.
pub struct FileMapPosition {
	/// The segment number containing the serialized virtual file map.
	pub segment_no: u64,
	/// The byte offset of the serialized virtual file map inside the appropriate segment.
	pub offset: u64
}

impl From<(u64, u64)> for FileMapPosition {
	fn from(value: (u64, u64)) -> Self {
		FileMapPosition { segment_no: value.0, offset: value.1 }
	}
}

/// The [FileMetadata] contains the appropriate metadata for a zff logical file or a zff virtual logical file.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FileMetadata {
	/// The file header describing the logical or virtual file.
	pub header: FileHeader,
	/// The file footer metadata containing file-specific trailing information.
	pub footer: FileFooterMetadata,
}

impl FileMetadata {
	/// creates a new [File] instance for the given [FileHeader] and [FileFooter].
	pub fn with_file_footer(header: FileHeader, footer: FileFooter) -> Self {
		Self {
			header,
			footer: FileFooterMetadata::FileFooter(footer),
		}
	}

	/// creates a new [File] instance for the given [FileHeader] and [VirtualFileFooter].
	pub fn with_virtual_file_footer(header: FileHeader, footer: VirtualFileFooter) -> Self {
		Self {
			header,
			footer: FileFooterMetadata::VirtualFileFooterMetadata(footer.into()),
		}
	}

	/// Returns the first chunk number used for the appropriate file.
	/// Returns Some(chunk_number) in case of a logical file and None in case of a virtual file.
	pub fn first_chunk_number(&self) -> Option<u64> {
		match &self.footer {
			FileFooterMetadata::VirtualFileFooterMetadata(_) => None,
			FileFooterMetadata::FileFooter(footer) => Some(footer.first_chunk_number),
		}
	}

	/// Returns the total number of chunks used for the appropriate file.
	/// Returns Some(number_of_chunks) in case of a logical file and None in case of a virtual file.
	pub fn number_of_chunks(&self) -> Option<u64> {
		match &self.footer {
			FileFooterMetadata::VirtualFileFooterMetadata(_) => None,
			FileFooterMetadata::FileFooter(footer) => Some(footer.number_of_chunks),
		}
	}

	/// Returns None in case of [FileFooter].
	pub(crate) fn vffc(&self) -> Result<&VirtualFileContent> {
		match &self.footer {
			FileFooterMetadata::FileFooter(_) => Err(ZffError::new(ZffErrorKind::Invalid, ERROR_ZFFREADER_MISSING_VFM)),
			FileFooterMetadata::VirtualFileFooterMetadata(footer) => {
				Ok(&footer.vfc)
			}
		}
	}

	/// returns the parent file number
	pub fn parent(&self) -> u64 {
		self.header.parent_file_number
	}

	/// returns the [FileType].
	pub fn filetype(&self) -> FileType {
		self.header.file_type.clone()
	}

	/// returns the length of the data, read from the underlying filefooter.
	pub fn length_of_data(&self) -> u64 {
		match &self.footer {
			FileFooterMetadata::FileFooter(footer) => footer.length_of_data,
			FileFooterMetadata::VirtualFileFooterMetadata(footer) => footer.length_of_data,
		}
	}
}

/// A Wrapper for logical objects [FileFooter] and virtual objects [VirtualFileFooterMetadata].
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum FileFooterMetadata {
	/// Contains a [FileFooter] used in logical objects.
	FileFooter(FileFooter),
	/// Contains a [VirtualFileFooterMetadata] used in virtual objects.
	VirtualFileFooterMetadata(VirtualFileFooterMetadata),
}
