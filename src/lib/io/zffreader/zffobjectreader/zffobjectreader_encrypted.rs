// - Parent
use super::*;

/// A reader which contains the appropriate metadata of a encrypted object 
/// (e.g. the appropriate [ObjectHeader](crate::header::ObjectHeader) and [ObjectFooter](crate::footer::ObjectFooter)).
#[derive(Debug)]
pub(crate) struct ZffObjectReaderEncrypted<R: Read + Seek> {
	encrypted_header: EncryptedObjectHeader,
	encrypted_footer: EncryptedObjectFooter,
	metadata: ArcZffReaderMetadata<R>,
}

impl<R: Read + Seek> ZffObjectReaderEncrypted<R> {
	/// creates a new [ZffObjectReaderEncrypted] with the given metadata.
	pub fn with_data(
		encrypted_header: EncryptedObjectHeader, 
		encrypted_footer: EncryptedObjectFooter, 
		metadata: ArcZffReaderMetadata<R>) -> Self {
		Self {
			encrypted_header,
			encrypted_footer,
			metadata,
		}
	}

	/// Tries to decrypt the [ZffObjectReader] with the given parameters.
	pub fn decrypt_with_password<P>(&mut self, password: P) -> Result<ZffObjectReader<R>> 
	where
		P: AsRef<[u8]>,
		R: Read + Seek,
	{
		let decrypted_object_header = self.encrypted_header.decrypt_with_password(password)?;
		let enc_info = EncryptionInformation::try_from(&decrypted_object_header)?;
		let decrypted_footer = self.encrypted_footer.decrypt(enc_info.encryption_key, enc_info.algorithm)?;

		let obj_no = decrypted_object_header.object_number;
		let obj_metadata = ObjectMetadata::new(decrypted_object_header, decrypted_footer.clone());
		self.metadata.object_metadata.write().unwrap().insert(obj_no, obj_metadata);

		let obj_reader = match decrypted_footer {
			ObjectFooter::Physical(_) => ZffObjectReader::Physical(Box::new(
				ZffObjectReaderPhysical::with_metadata(
					obj_no, 
					Arc::clone(&self.metadata)))),
			ObjectFooter::Logical(_) => ZffObjectReader::Logical(Box::new(
				ZffObjectReaderLogical::with_obj_metadata_recommended(
					obj_no, 
					Arc::clone(&self.metadata))?)),
			ObjectFooter::Virtual(_) => ZffObjectReader::Virtual(Box::new(
				ZffObjectReaderVirtual::with_data(
					obj_no,
					Arc::clone(&self.metadata))?)),
			ObjectFooter::VirtualLogical(_) => ZffObjectReader::VirtualLogical(Box::new(
				ZffObjectReaderVirtualLogical::with_data(
					obj_no,
					Arc::clone(&self.metadata))?)),
		};

		Ok(obj_reader)

	}
}
