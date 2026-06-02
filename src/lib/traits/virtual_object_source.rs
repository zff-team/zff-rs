// - Parent
use crate::prelude::*;

/// Trait for abstracting different file input sources for [VirtualObjectSource].
pub trait VirtualObjectSource: Iterator<Item = Result<(FileHeader, VirtualFileFooterMetadata)>> {
	/// Returns the remaining elements of the inner iterator
	fn remaining_elements(&self) -> u64;

	/// Returns the file numbers of root directories.
	fn root_dir_filenumbers(&self) -> &Vec<u64>;
}