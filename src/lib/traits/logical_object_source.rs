// - Parent
use super::{*, header::*};

/// Trait for abstracting different file input sources for [LogicalObjectEncoder].
pub trait LogicalObjectSource: Iterator<Item = (Result<FileTypeEncodingInformation>, FileHeader)> {
	/// Returns the remaining elements of the inner iterator
	fn remaining_elements(&self) -> u64;

	/// Returns the file numbers of root directories.
	fn root_dir_filenumbers(&self) -> &Vec<u64>;

	/// Returns a mapping of file numbers to their symlink real paths.
	fn symlink_real_paths(&self) -> &HashMap<u64, PathBuf>;

	/// Returns a mapping of hardlink file numbers to their target file numbers.
	fn hardlink_map(&self) -> &HashMap<u64, u64>;

	/// Returns a mapping of directory file numbers to their children file numbers.
	fn directory_children(&self) -> &HashMap<u64, Vec<u64>>;
}