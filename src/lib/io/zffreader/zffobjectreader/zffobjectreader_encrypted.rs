// - Parent
use super::*;

/// A reader which contains the appropriate metadata of a encrypted object
/// (e.g. the appropriate [ObjectHeader](crate::header::ObjectHeader) and [ObjectFooter](crate::footer::ObjectFooter)).
#[derive(Debug)]
pub(crate) struct ZffObjectReaderEncrypted<R: ReadAt> {
    encrypted_header: EncryptedObjectHeader,
    encrypted_footer: EncryptedObjectFooter,
    metadata: ArcZffReaderMetadata<R>,
}

impl<R: ReadAt> ZffObjectReaderEncrypted<R> {
    /// creates a new [ZffObjectReaderEncrypted] with the given metadata.
    pub fn new(
        encrypted_header: EncryptedObjectHeader,
        encrypted_footer: EncryptedObjectFooter,
        metadata: ArcZffReaderMetadata<R>,
    ) -> Self {
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
    {
        let decrypted_object_header = self.encrypted_header.decrypt_with_password(password)?;
        let enc_info = EncryptionInformation::try_from(&decrypted_object_header)?;
        let decrypted_footer = self
            .encrypted_footer
            .decrypt(enc_info.encryption_key, enc_info.algorithm)?;

        let obj_no = decrypted_object_header.object_number;
        let obj_metadata = ObjectMetadata::new(decrypted_object_header, decrypted_footer.clone());
        self.metadata
            .object_metadata
            .get(&obj_no)
            .ok_or_else(|| {
                ZffError::new(
                    ZffErrorKind::Missing,
                    format!("{ERROR_MISSING_OBJECT_NO}{obj_no}"),
                )
            })?
            .set(obj_metadata)
            .map_err(|_| {
                ZffError::new(
                    ZffErrorKind::Invalid,
                    format!("object already initialized: {obj_no}"),
                )
            })?;

        let obj_reader = match decrypted_footer {
            ObjectFooter::Physical(_) => ZffObjectReader::Physical(Box::new(
                ZffObjectReaderPhysical::new(obj_no, Arc::clone(&self.metadata)),
            )),
            ObjectFooter::Logical(_) => ZffObjectReader::Logical(Box::new(
                ZffObjectReaderLogical::new(obj_no, Arc::clone(&self.metadata))?,
            )),
            ObjectFooter::Virtual(_) => ZffObjectReader::Virtual(Box::new(
                ZffObjectReaderVirtual::new(obj_no, Arc::clone(&self.metadata))?,
            )),
        };

        Ok(obj_reader)
    }
}
