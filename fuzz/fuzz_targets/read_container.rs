#![no_main]
//! Fuzzes the reader over a whole container.
//!
//! This drives the paths a forensic tool actually uses on an untrusted image:
//! parsing the segment, enumerating objects, and reading object data.

use std::io::{Cursor, Read};
use std::sync::Mutex;

use libfuzzer_sys::fuzz_target;
use zff::io::zffreader::ZffReader;

fuzz_target!(|data: &[u8]| {
    let Ok(mut reader) = ZffReader::with_reader(vec![Mutex::new(Cursor::new(data.to_vec()))]) else {
        return;
    };
    let Ok(objects) = reader.list_objects() else {
        return;
    };

    for object_number in objects.keys().copied().collect::<Vec<_>>() {
        if reader.initialize_object(object_number).is_err() {
            continue;
        }
        if reader.set_active_object(object_number).is_err() {
            continue;
        }
        // Bounded, so a corrupted length cannot turn into an endless read.
        let mut output = Vec::new();
        let _ = reader.by_ref().take(1 << 20).read_to_end(&mut output);
    }
});
