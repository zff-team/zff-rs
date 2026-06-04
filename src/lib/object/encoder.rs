// - STD
use std::io::Read;

// - internal
use crate::prelude::*;
use crate::{
	LogicalObjectEncoder,
	PhysicalObjectEncoder,
	PreparedChunk,
	VirtualObjectEncoder,
};

/// Returns the current state of encoding.
#[derive(Debug, Clone, Default)]
pub(crate) enum EncodingState {
	/// Returns a prepared chunk.
	PreparedChunk(PreparedChunk),
	/// returns prepared data (contains a prepared chunk, a file header or a file footer).
	PreparedData(PreparedData),
	/// is used, if the source reader reaches a EOF state.
	#[default]
	ReadEOF,
}

/// Contains a prepared data object. This can be a [PreparedChunk], a [PreparedFileHeader] or a [PreparedFileFooter].
#[derive(Debug, Clone)]
pub(crate) enum PreparedData {
	/// A prepared chunk.
	PreparedChunk(PreparedChunk),
	/// A prepared file header.
	PreparedFileHeader(Vec<u8>),
	/// A prepared file footer.
	PreparedFileFooter(Vec<u8>),
	/// A VFM
	PreparedVFM(Vec<u8>),
}

impl PreparedData {
	/// Returns a reference to the inner data
	pub fn inner_data_ref(&self) -> &Vec<u8> {
		match self {
			Self::PreparedChunk(value) => &value.data,
			Self::PreparedFileFooter(value) => value,
			Self::PreparedFileHeader(value) => value,
			Self::PreparedVFM(value) => value
		}
	}
}

/// An encoder for each object.
///
/// This is a wrapper enum that can contain any of the object encoder types.
pub enum ObjectEncoder<R: Read> {
	/// Physical object encoder.
	Physical(Box<PhysicalObjectEncoder<R>>),
	/// Logical object encoder.
	Logical(Box<LogicalObjectEncoder>),
	/// Virtual object encoder.
	Virtual(Box<VirtualObjectEncoder>),
}

impl<R: Read> ObjectEncoder<R> {
	/// returns the appropriate object number.
	pub fn obj_number(&self) -> u64 {
		match self {
			ObjectEncoder::Physical(obj) => obj.obj_number(),
			ObjectEncoder::Logical(obj) => obj.obj_number(),
			ObjectEncoder::Virtual(obj) => obj.obj_number(),
		}
	}

	/// returns the current chunk number.
	pub fn current_chunk_number(&self) -> u64 {
		match self {
			ObjectEncoder::Physical(obj) => obj.current_chunk_number,
			ObjectEncoder::Logical(obj) => obj.current_chunk_number,
			ObjectEncoder::Virtual(_) => 0,
		}
	}

	/// returns a reference of the appropriate [ObjectHeader].
	pub fn get_obj_header(&self) -> &ObjectHeader {
		match self {
			ObjectEncoder::Physical(obj) => &obj.obj_header,
			ObjectEncoder::Logical(obj) => &obj.obj_header,
			ObjectEncoder::Virtual(obj) => &obj.obj_header,
		}
	}

	/// returns the appropriate encoded [ObjectHeader].
	pub fn get_encoded_header(&mut self) -> Vec<u8> {
		match self {
			ObjectEncoder::Physical(obj) => obj.get_encoded_header(),
			ObjectEncoder::Logical(obj) => obj.get_encoded_header(),
			ObjectEncoder::Virtual(obj) => obj.get_encoded_header(),
		}
	}

	/// returns the appropriate object footer.
	pub fn get_encoded_footer(&mut self) -> Result<Vec<u8>> {
		match self {
			ObjectEncoder::Physical(obj) => obj.get_encoded_footer(),
			ObjectEncoder::Logical(obj) => obj.get_encoded_footer(),
			ObjectEncoder::Virtual(obj) => obj.get_encoded_footer(),
		}
	}

	/// returns the next data.
	pub(crate) fn get_next_data<D: ReadAt>(
		&mut self, 
		current_offset: u64, 
		current_segment_no: u64, 
		deduplication_metadata: Option<&mut DeduplicationMetadata<D>>
		) -> Result<EncodingState> {
		match self {
			ObjectEncoder::Physical(obj) => obj.get_next_chunk(deduplication_metadata),
			ObjectEncoder::Logical(obj) => obj.get_next_data(current_offset, current_segment_no, deduplication_metadata),
			ObjectEncoder::Virtual(obj) => obj.get_next_data(current_offset, current_segment_no),
		}
	}

	/// Returns the total number of files left in the object encoder.
	/// Will return None if the object encoder is not a logical object encoder.
	pub fn files_left(&self) -> Option<u64> {
		match self {
			ObjectEncoder::Physical(_) => None,
			ObjectEncoder::Logical(obj) => Some(obj.logical_object_source.remaining_elements()),
			ObjectEncoder::Virtual(obj) => Some(obj.virtual_object_source.remaining_elements()),
		}
	}
}