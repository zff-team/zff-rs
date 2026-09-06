// - STD
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::Cursor;

// - internal
use crate::prelude::*;

// - external
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The SegmentFooter is a footer which is be written at the end of each segment.
///
/// The footer contains a table on the chunks, present in the appropriate segment.
/// The offset table is internally managed as a ```HashMap<u64, u64>```.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Deserialize))]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct SegmentFooter {
    /// The total length of the segment.
    pub length_of_segment: u64,
    /// A [HashMap] containing the object number and the appropriate offset of the [crate::header::ObjectHeader].
    pub object_header_offsets: HashMap<u64, u64>, //<object number, offset>,
    /// A [HashMap] containing the object number and the appropriate offset of the [crate::footer::ObjectFooter].
    pub object_footer_offsets: HashMap<u64, u64>, //<object number, offset>,
    /// [BTreeMap] containing the chunk number and the appropriate offset of the chunkmaps.
    pub chunk_header_map_table: BTreeMap<u64, u64>, //<highest chunk number, offset>
    /// [BTreeMap] containing the chunk number and the appropriate offset of the chunkmaps.
    pub chunk_samebytes_map_table: BTreeMap<u64, u64>, //<highest chunk number, offset>
    /// [BTreeMap] containing the chunk number and the appropriate offset of the chunkmaps.
    pub chunk_dedup_map_table: BTreeMap<u64, u64>, //<highest chunk number, offset>
    /// The first chunk number which was used in this segment.
    pub first_chunk_number: u64,
    /// The offset where the footer starts.
    pub footer_offset: u64,
}

impl Default for SegmentFooter {
    fn default() -> Self {
        SegmentFooter::new_empty()
    }
}

impl SegmentFooter {
    /// Returns the encoded size of this footer without encoding it.
    ///
    /// [HeaderCoding::header_size](crate::header::HeaderCoding::header_size)
    /// determines the size by encoding the whole footer into a fresh buffer.
    /// The writer needs this size once per chunk to decide whether the current
    /// segment still has room, so it is computed arithmetically here instead.
    /// Every field is a u64 or a map of u64 to u64, which makes this exact.
    pub(crate) fn encoded_size(&self) -> usize {
        // Every map is encoded as an u64 length followed by u64 key/value pairs.
        let encoded_map_size =
            |entries: usize| ENCODED_MAP_LENGTH_SIZE + entries * ENCODED_U64_PAIR_SIZE;

        DEFAULT_LENGTH_HEADER_IDENTIFIER // the header identifier
            + DEFAULT_LENGTH_VALUE_HEADER_LENGTH // the header length value itself
            + ENCODED_VERSION_SIZE
            + ENCODED_U64_SIZE // length_of_segment
            + encoded_map_size(self.object_header_offsets.len())
            + encoded_map_size(self.object_footer_offsets.len())
            + encoded_map_size(self.chunk_header_map_table.len())
            + encoded_map_size(self.chunk_samebytes_map_table.len())
            + encoded_map_size(self.chunk_dedup_map_table.len())
            + ENCODED_U64_SIZE // first_chunk_number
            + ENCODED_U64_SIZE // footer_offset
    }

    /// creates a new empty SegmentFooter.
    pub fn new_empty() -> SegmentFooter {
        Self {
            length_of_segment: 0,
            object_header_offsets: HashMap::new(),
            object_footer_offsets: HashMap::new(),
            chunk_header_map_table: BTreeMap::new(),
            chunk_samebytes_map_table: BTreeMap::new(),
            chunk_dedup_map_table: BTreeMap::new(),
            first_chunk_number: INITIAL_CHUNK_NUMBER,
            footer_offset: 0,
        }
    }

    /// creates a new SegmentFooter.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        length_of_segment: u64,
        object_header_offsets: HashMap<u64, u64>,
        object_footer_offsets: HashMap<u64, u64>,
        chunk_header_map_table: BTreeMap<u64, u64>,
        chunk_samebytes_map_table: BTreeMap<u64, u64>,
        chunk_dedup_map_table: BTreeMap<u64, u64>,
        first_chunk_number: u64,
        footer_offset: u64,
    ) -> SegmentFooter {
        Self {
            length_of_segment,
            object_header_offsets,
            object_footer_offsets,
            chunk_header_map_table,
            chunk_samebytes_map_table,
            chunk_dedup_map_table,
            first_chunk_number,
            footer_offset,
        }
    }
}

impl HeaderCoding for SegmentFooter {
    type Item = Self;

    fn identifier() -> u32 {
        FOOTER_IDENTIFIER_SEGMENT_FOOTER
    }

    fn version() -> u8 {
        DEFAULT_FOOTER_VERSION_SEGMENT_FOOTER
    }

    fn encode_content(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.length_of_segment.encode_directly());
        vec.extend_from_slice(&self.object_header_offsets.encode_directly());
        vec.extend_from_slice(&self.object_footer_offsets.encode_directly());
        vec.extend_from_slice(&self.chunk_header_map_table.encode_directly());
        vec.extend_from_slice(&self.chunk_samebytes_map_table.encode_directly());
        vec.extend_from_slice(&self.chunk_dedup_map_table.encode_directly());
        vec.extend_from_slice(&self.first_chunk_number.encode_directly());
        vec.extend_from_slice(&self.footer_offset.encode_directly());
        vec
    }

    fn decode_content(data: &[u8]) -> Result<SegmentFooter> {
        let mut cursor = Cursor::new(data);
        Self::check_version(&mut cursor)?;
        let length_of_segment = u64::decode_directly(&mut cursor)?;
        let object_header_offsets = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
        let object_footer_offsets = HashMap::<u64, u64>::decode_directly(&mut cursor)?;
        let chunk_header_map_table = BTreeMap::<u64, u64>::decode_directly(&mut cursor)?;
        let chunk_samebytes_map_table = BTreeMap::<u64, u64>::decode_directly(&mut cursor)?;
        let chunk_dedup_map_table = BTreeMap::<u64, u64>::decode_directly(&mut cursor)?;
        let first_chunk_number = u64::decode_directly(&mut cursor)?;
        let footer_offset = u64::decode_directly(&mut cursor)?;
        Ok(SegmentFooter::new(
            length_of_segment,
            object_header_offsets,
            object_footer_offsets,
            chunk_header_map_table,
            chunk_samebytes_map_table,
            chunk_dedup_map_table,
            first_chunk_number,
            footer_offset,
        ))
    }
}

// - implement fmt::Display
impl fmt::Display for SegmentFooter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Self::struct_name())
    }
}
