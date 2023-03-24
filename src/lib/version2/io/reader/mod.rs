// - STD
use std::collections::HashMap;
use std::io::{Read,Seek,SeekFrom};

// modules
mod zffmetadatareader;
mod zffobjectreader;
mod zffreader;

// re-exports
pub use zffmetadatareader::*;
pub use zffobjectreader::*;
pub use zffreader::*;

// - internal
use crate::{
	Result,
	Segment,
	HeaderCoding,
	ValueDecoder,
	ZffError,
	ZffErrorKind,
	footer::{MainFooter},
	Object,
};

use crate::{
	ERROR_MISSING_SEGMENT_MAIN_FOOTER
};

fn find_mainfooter<R: Read + Seek>(data: &mut R) -> Result<MainFooter> {
	data.seek(SeekFrom::End(-8))?;
	let footer_offset = u64::decode_directly(data)?;
	data.seek(SeekFrom::Start(footer_offset))?;
	match MainFooter::decode_directly(data) {
		Ok(mf) => {
			data.rewind()?;
			Ok(mf)
		},
		Err(e) => match e.get_kind() {
			ZffErrorKind::HeaderDecodeMismatchIdentifier => {
				data.rewind()?;
				Err(ZffError::new(ZffErrorKind::Custom, ERROR_MISSING_SEGMENT_MAIN_FOOTER))
			},
			_ => Err(e)
		}
	}
}

/// returns if the appropriate object is partial or full encrypted (or unencrypted)
fn objectstate<R: Read + Seek>(segment: &mut Segment<R>, object_number: u64) -> Result<ObjectState> {
	let obj_header = match segment.read_object_header(object_number) {
		Ok(header) => header,
		Err(e) => match e.get_kind() {
			ZffErrorKind::HeaderDecodeEncryptedHeader => return Ok(ObjectState::EncryptedHeader),
			_ => return Err(e),
		}
	};
	if obj_header.encryption_header().is_some() {
		Ok(ObjectState::EncryptedData)
	} else {
		Ok(ObjectState::Unencrypted)
	}
}

#[derive(PartialEq)]
enum ObjectState {
	Unencrypted,
	EncryptedData,
	EncryptedHeader,
}

// returns the appropriate object
fn get_object<R: Read + Seek, P:Into<String>>(
	segments: &mut HashMap<u64, Segment<R>>, 
	main_footer: &MainFooter, 
	decryption_password: Option<P>,
	object_number: u64) -> Result<Object> {

	let object_footer = {
		match main_footer.object_footer().get(&object_number) {
			Some(segment_no) => {
				let segment_with_obj_footer = match segments.get_mut(segment_no) {
					Some(s) => s,
					None => return Err(ZffError::new(ZffErrorKind::MissingSegment, object_number.to_string())),
				};
				segment_with_obj_footer.read_object_footer(object_number)?
			},
			None => return Err(ZffError::new(ZffErrorKind::MissingSegment, object_number.to_string())),
		}
	};

	let (encryption_key, object_header) = match main_footer.object_header().get(&object_number) {
		Some(segment_no) => {
			let segment_with_obj_header = match segments.get_mut(segment_no) {
				Some(s) => s,
				None => return Err(ZffError::new(ZffErrorKind::MissingSegment, object_number.to_string())),
			};
			match objectstate(segment_with_obj_header, object_number)? {
				ObjectState::Unencrypted => (None, segment_with_obj_header.read_object_header(object_number)?),
				ObjectState::EncryptedHeader => {
					let decryption_password = match decryption_password {
						Some(x) => x.into(),
						None => return Err(ZffError::new(ZffErrorKind::MissingPassword, "")),
					};
					match segment_with_obj_header.read_encrypted_object_header(object_number, &decryption_password) {
						Ok(obj_header) => {
							// unwrap should be safe here, because the object header could decryption without a present encryption header.
							//TODO: Find a better way to handle this - there are two decryption processes to get the encryption_key?!
							let enc_key = Some(obj_header.encryption_header().unwrap().decrypt_encryption_key(decryption_password)?);
							(enc_key, obj_header)
						},
						Err(e) => return Err(ZffError::new(ZffErrorKind::DecryptionOfEncryptionKey, e.to_string())),
					}
				},
				ObjectState::EncryptedData => {
					let decryption_password = match decryption_password {
						Some(x) => x.into(),
						None => return Err(ZffError::new(ZffErrorKind::MissingPassword, "")),
					};
					match segment_with_obj_header.read_object_header(object_number) {
						Ok(obj_header) => {
							// unwrap should be safe here, because the object header could decryption without a present encryption header.
							let enc_key = Some(obj_header.encryption_header().unwrap().decrypt_encryption_key(decryption_password)?);
							(enc_key, obj_header)
						},
						Err(e) => return Err(ZffError::new(ZffErrorKind::MalformedHeader, e.to_string()))
					}
				},
			}
		},
		None => return Err(ZffError::new(ZffErrorKind::MissingObjectNumber, object_number.to_string())),
	};

	let object = Object::new(object_header, object_footer, encryption_key.clone());
	
	// Test if the extracted encryption/decryption key works or not.
	if let Some(encryption_key) = encryption_key {
		let encryption_algorithm = object.header().encryption_header().unwrap().algorithm().clone();
		let chunk_no = match object {
			Object::Physical(ref obj) => obj.footer().first_chunk_number(),
			Object::Logical(ref obj) => {
				let file = match obj.files().values().next() {
					Some(x) => x,
					None => return Err(ZffError::new(ZffErrorKind::NoFilesLeft, "")),
				};
				file.footer().first_chunk_number()
			}
		};
		for segment in segments.values_mut() {
			if segment.footer().chunk_offsets().contains_key(&chunk_no) {
				match segment.test_decrypt_chunk(chunk_no, encryption_key, &encryption_algorithm)? {
					true => return Ok(object),
					false => return Err(ZffError::new(ZffErrorKind::EncryptionError, "Wrong password?")),
				}
			}
		}
		return Err(ZffError::new(ZffErrorKind::MissingSegment, ""));
	}
	Ok(object)
}