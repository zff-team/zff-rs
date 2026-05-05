// - Parent
use super::{*, header::*, footer::*, io::{buffer_chunk, BufferedChunk}};

// - modules
mod file_encoder;
mod virtual_file_encoder;

// - re-exports
pub use file_encoder::*;
pub use virtual_file_encoder::*;

#[derive(Debug,Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct VirtualFileFooterMetadata {
	pub hash_header: HashHeader,
    pub length_of_data: u64,
    pub vfc: VirtualFileContent,
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


#[derive(Debug,Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum VirtualFileContent {
	FileMap(VirtualFileMap), // contains the real VFM
	FileMapPosition(u64, u64), // contains (segment_no, offset) the appropriate filemap
	Directory(Vec<u64>),
	Symlink(PlatformString),
	Hardlink(u64),
	SpecialFile(u64, SpecialFileType) //rdev-id, type
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

pub struct FileMapPosition {
	pub segment_no: u64,
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
	pub header: FileHeader,
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

	pub(crate) fn first_chunk_number(&self) -> Option<u64> {
		match &self.footer {
			FileFooterMetadata::VirtualFileFooterMetadata(_) => None,
			FileFooterMetadata::FileFooter(footer) => Some(footer.first_chunk_number),
		}
	}

	pub(crate) fn number_of_chunks(&self) -> Option<u64> {
		match &self.footer {
			FileFooterMetadata::VirtualFileFooterMetadata(_) => None,
			FileFooterMetadata::FileFooter(footer) => Some(footer.number_of_chunks),
		}
	}

	/// Returns None in case of [FileFooter].
	pub(crate) fn vffc(&self) -> Result<&VirtualFileContent> {
		match &self.footer {
			FileFooterMetadata::FileFooter(_) => return Err(ZffError::new(ZffErrorKind::Invalid, ERROR_ZFFREADER_MISSING_VFM)),
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum FileFooterMetadata {
	FileFooter(FileFooter),
	VirtualFileFooterMetadata(VirtualFileFooterMetadata),
}
