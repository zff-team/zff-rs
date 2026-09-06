#![no_main]
//! Fuzzes every header, footer and structure decoder with arbitrary bytes.
//!
//! Lengths and offsets inside a zff container are attacker controlled, so a
//! decoder must reject malformed input with an error rather than panicking,
//! aborting on an over-sized allocation, or looping.

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use zff::header::*;
use zff::footer::*;
use zff::prelude::*;

fuzz_target!(|data: &[u8]| {
    macro_rules! try_decode {
        ($($ty:ty),* $(,)?) => {
            $(
                let _ = <$ty>::decode_directly(&mut Cursor::new(data));
            )*
        };
    }

    try_decode!(
        SegmentHeader,
        ObjectHeader,
        FileHeader,
        CompressionHeader,
        DescriptionHeader,
        EncryptionHeader,
        PBEHeader,
        HashHeader,
        SegmentFooter,
        MainFooter,
        ObjectFooterPhysical,
        ObjectFooterLogical,
        ObjectFooterVirtual,
        FileFooter,
    );
    let _ = <ChunkHeader as HeaderCoding>::decode_directly(&mut Cursor::new(data));
});
