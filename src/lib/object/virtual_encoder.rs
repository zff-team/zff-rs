// - STD
use std::time::SystemTime;

// - internal
use crate::prelude::*;
use crate::{
    EncodingState,
    PreparedData,
    VirtualFileContent,
    VirtualFileEncoder,
    Signature,
};

// - external
use time::{OffsetDateTime};
use ed25519_dalek::{SigningKey};
use zeroize::Zeroize;

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReadState {
    /// The next call emits the current virtual file header.
    FileHeader,
    /// The next call emits the current virtual file map.
    Vfm,
    /// The next call emits the current virtual file footer.
    FileFooter,
}

/// Encodes a virtual object.
///
/// A virtual object stores file metadata and references to existing data instead
/// of emitting file chunks directly. For each entry yielded by the configured
/// [VirtualObjectSource], this encoder emits the encoded [FileHeader], an
/// optional [VirtualFileMap], and the encoded [VirtualFileFooter].
///
/// The caller provides the current segment number and offset for every emitted
/// item. The encoder stores those locations in the [ObjectFooterVirtual] so
/// readers can later resolve every virtual file header and footer inside the
/// container.
pub struct VirtualObjectEncoder {
	/// The appropriate original object header
	pub(crate) obj_header: ObjectHeader,
	/// Object footer populated while virtual file headers and footers are emitted.
	pub(crate) obj_footer: ObjectFooterVirtual,
	/// Source that yields virtual file headers and footer metadata.
	pub(crate) virtual_object_source: Box<dyn VirtualObjectSource>,
	/// Encoder for the virtual file currently being emitted.
	pub(crate) current_file_encoder: Option<VirtualFileEncoder>,
    /// Encryption information derived from the object header, if the object is encrypted.
    enc_info: Option<EncryptionInformation>,
    /// Optional signing key used to sign virtual file hash values.
    signing_key: Option<SigningKey>,
    /// Current position in the per-file emission state machine.
    read_state: ReadState,
}

impl Drop for VirtualObjectEncoder {
    fn drop(&mut self) {
        self.enc_info.zeroize();
    }
}

impl VirtualObjectEncoder {
    /// Creates a new [VirtualObjectEncoder].
    ///
    /// The encoder immediately reads the first virtual file from
    /// virtual_object_source and prepares a [VirtualFileEncoder] for it. If
    /// the source is empty, the encoder is created without a current file and
    /// [Self::get_next_data] will return [EncodingState::ReadEOF].
    ///
    /// Encryption settings are derived from `obj_header` and reused for all
    /// encoded virtual file headers, virtual file maps, virtual file footers, and
    /// the final object footer.
    ///
    /// # Errors
    ///
    /// Returns an error if the first entry yielded by virtual_object_source
    /// cannot be read or converted into a [VirtualFileEncoder].
    pub fn new(
        obj_header: ObjectHeader,
        mut virtual_object_source: Box<dyn VirtualObjectSource>,
        signing_key_bytes: Option<Vec<u8>>,
    ) -> Result<Self> {
        let obj_footer = ObjectFooterVirtual::new_empty(obj_header.object_number);
        let enc_info = EncryptionInformation::try_from(&obj_header).ok();
        let signing_key = match &signing_key_bytes {
            Some(bytes) => Some(Signature::bytes_to_signingkey(bytes)?),
            None => None,
        };
        let current_file_encoder =
            next_virtual_file_encoder(&mut virtual_object_source, &enc_info, &signing_key)?;
        Ok(Self {
            obj_header,
            obj_footer,
            virtual_object_source,
            current_file_encoder,
            enc_info,
            signing_key,
            read_state: ReadState::FileHeader,
        })
    }

	/// Returns the appropriate object number.
	pub fn obj_number(&self) -> u64 {
		self.obj_header.object_number
	}

	/// Returns a reference to the [ObjectHeader].
	pub fn object_header(&self) -> &ObjectHeader {
		&self.obj_header
	}

	/// Returns the encoded object header.
    ///
    /// If the object header contains encryption information, the encrypted
    /// header representation is returned. Otherwise the plain encoded header is
    /// returned.
	pub fn get_encoded_header(&mut self) -> Vec<u8> {
		if let Some(encryption_key) = &self.enc_info.as_ref().map(|enc_info| &enc_info.encryption_key) {
			//unwrap should be safe here, because we have already testet this before.
	    	self.obj_header.encode_encrypted_header_directly(encryption_key).unwrap()
	    } else {
	    	self.obj_header.encode_directly()
	    }
	}

    /// Returns the next encoded virtual object item.
    ///
    /// The method advances through one virtual file at a time in this order:
    ///
    /// 1. encoded [FileHeader]
    /// 2. encoded [VirtualFileMap], if the file is backed by a file map
    /// 3. encoded [VirtualFileFooter]
    ///
    /// `current_offset` and `current_segment_no` must point to the item that is
    /// about to be written. They are recorded in the virtual object footer for
    /// file headers and file footers. When the current file footer has been
    /// emitted, the next file is pulled from [Self::virtual_object_source].
    ///
    /// # Errors
    ///
    /// Returns an error if the source fails while yielding the next virtual file
    /// or if a virtual file map cannot be encoded with the configured encryption
    /// settings.
    pub(crate) fn get_next_data(
		&mut self, 
		current_offset: u64, 
		current_segment_no: u64) -> Result<EncodingState> {
        match self.current_file_encoder {
            None => Ok(EncodingState::ReadEOF),
            Some(ref mut file_encoder) => {
                match self.read_state {
                    ReadState::FileHeader => {
                        if file_encoder.vfm.is_some() {
                            self.read_state = ReadState::Vfm;
                        } else {
                            self.read_state = ReadState::FileFooter;
                        }
                        self.obj_footer.file_header_segment_numbers.insert(file_encoder.file_header.file_number, current_segment_no);
                        self.obj_footer.file_header_offsets.insert(file_encoder.file_header.file_number, current_offset);

                        Ok(EncodingState::PreparedData(PreparedData::PreparedFileHeader(file_encoder.encoded_header())))
                    },
                    ReadState::Vfm => {
                        self.read_state = ReadState::FileFooter;
                        file_encoder.file_footer.vffc = VirtualFileFooterContent::FileMap(current_segment_no, current_offset);
                        // unwrap should be safe at this point: We will only reach the ReadState::VFM through ReadState::FileHeader
                        // which always ensures hat the VFM exists.
                        Ok(EncodingState::PreparedData(PreparedData::PreparedVFM(file_encoder.encoded_vfm()?.unwrap())))
                    },
                    ReadState::FileFooter => {
                        self.read_state = ReadState::FileHeader;
                        self.obj_footer.file_footer_segment_numbers.insert(file_encoder.file_header.file_number, current_segment_no);
                        self.obj_footer.file_footer_offsets.insert(file_encoder.file_header.file_number, current_offset);
                        let encoding_state = EncodingState::PreparedData(PreparedData::PreparedFileHeader(file_encoder.encoded_footer()));
                        match self.virtual_object_source.next() {
                            None => self.current_file_encoder = None,
                            Some(virtual_source) => {
                                let (file_header, mut vffm) = virtual_source?;
                                sign_hash_header(&mut vffm.hash_header, &self.signing_key);
                                let vff = VirtualFileFooter::new(
                                    file_header.file_number,
                                    vffm.hash_header,
                                    vffm.length_of_data,
                                    vffm.vfc.clone().into(),
                                );
                                let vfm = match vffm.vfc {
                                    VirtualFileContent::FileMap(vfm) => Some(vfm),
                                    _ => None
                                };
                                self.current_file_encoder = Some(VirtualFileEncoder::new(file_header, vff, vfm, self.enc_info.clone()));
                            }
                        }

                        Ok(encoding_state)
                    }
                }
            }
        }
    }

	/// Returns the encoded footer for this object.
	///
	/// Before encoding, this method copies the source's root directory file
	/// numbers into the footer and sets the creation timestamp to the current
	/// system time.
	///
	/// # Errors
	///
	/// Returns an error if encrypting the footer fails.
	pub fn get_encoded_footer(&mut self) -> Result<Vec<u8>> {
		self.obj_footer.root_dir_filenumbers = self.virtual_object_source.root_dir_filenumbers().clone();
		let systemtime = OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64;
		self.obj_footer.creation_timestamp = systemtime;
		if let Some(enc_info) = &self.enc_info {
	    	self.obj_footer.encrypt_directly(enc_info)
	    } else {
	    	Ok(self.obj_footer.encode_directly())
	    }
	}

}


/// Reads the next virtual file from `virtual_object_source` and wraps it in a
/// [VirtualFileEncoder].
///
/// Returns `Ok(None)` when the source has no further files.
fn next_virtual_file_encoder(
    virtual_object_source: &mut Box<dyn VirtualObjectSource>,
    enc_info: &Option<EncryptionInformation>,
    signing_key: &Option<SigningKey>,
) -> Result<Option<VirtualFileEncoder>> {
    match virtual_object_source.next() {
        None => Ok(None),
        Some(virtual_source) => {
            let (file_header, mut vffm) = virtual_source?;
            sign_hash_header(&mut vffm.hash_header, signing_key);
            let vff = VirtualFileFooter::new(
                file_header.file_number,
                vffm.hash_header,
                vffm.length_of_data,
                vffm.vfc.clone().into(),
            );
            let vfm = match vffm.vfc {
                VirtualFileContent::FileMap(vfm) => Some(vfm),
                _ => None
            };
            Ok(Some(VirtualFileEncoder::new(
                file_header,
                vff,
                vfm,
                enc_info.clone(),
            )))
        }
    }
}

fn sign_hash_header(hash_header: &mut HashHeader, signing_key: &Option<SigningKey>) {
    if let Some(signing_key) = signing_key {
        for hash_value in &mut hash_header.hashes {
            let signature = Signature::sign(signing_key, &hash_value.hash);
            hash_value.set_ed25519_signature(signature);
        }
    }
}
