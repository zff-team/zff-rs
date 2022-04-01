// - STD
use std::io::Read;

// - internal
use crate::{
    Result,
    ZffError,
    ZffErrorKind,
};

// returns the buffer with the read bytes and the number of bytes which was read.
pub(crate) fn buffer_chunk<R>(
	input: &mut R,
	chunk_size: usize,
	) -> Result<(Vec<u8>, u64)> 
where
	R: Read
{
	let mut buf = vec![0u8; chunk_size];
    let mut bytes_read = 0;

    while bytes_read < chunk_size {
        let r = match input.read(&mut buf[bytes_read..]) {
        	Ok(r) => r,
        	Err(e) => match e.kind() {
        		std::io::ErrorKind::Interrupted => return Err(ZffError::new(ZffErrorKind::InterruptedInputStream, "")),
        		_ => return Err(ZffError::from(e)),
        	},
        };
        if r == 0 {
            break;
        }
        bytes_read += r;
    }

    let buf = if bytes_read == chunk_size {
        buf
    } else {
        buf[..bytes_read].to_vec()
    };
    Ok((buf, bytes_read as u64))
}