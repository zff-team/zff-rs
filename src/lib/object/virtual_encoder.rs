// - Parent
use super::{*, footer::*};

enum ReadState {
    FileHeader,
    Vfm,
    FileFooter,
}

/// The [VirtualObjectEncoder] can be used to encode a logical object.
pub struct VirtualObjectEncoder {
	/// The appropriate original object header
	pub(crate) obj_header: ObjectHeader,
	pub(crate) obj_footer: ObjectFooterVirtual,
	pub(crate) encryption_key: Option<Vec<u8>>,
	pub(crate) virtual_object_source: Box<dyn VirtualObjectSource>,
	pub(crate) current_file_encoder: Option<VirtualFileEncoder>,
    read_state: ReadState,
}

impl VirtualObjectEncoder {
	/// Returns the appropriate object number.
	pub fn obj_number(&self) -> u64 {
		self.obj_header.object_number
	}

	/// Returns a reference to the [ObjectHeader].
	pub fn object_header(&self) -> &ObjectHeader {
		&self.obj_header
	}

	/// Returns the encoded object header.
	pub fn get_encoded_header(&mut self) -> Vec<u8> {
		if let Some(encryption_key) = &self.encryption_key {
			//unwrap should be safe here, because we have already testet this before.
	    	self.obj_header.encode_encrypted_header_directly(encryption_key).unwrap()
	    } else {
	    	self.obj_header.encode_directly()
	    }
	}

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
                        Ok(EncodingState::PreparedData(PreparedData::PreparedFileHeader(file_encoder.encoded_header())))
                    },
                    ReadState::Vfm => {
                        file_encoder.file_footer.vffc = VirtualFileFooterContent::FileMap(current_segment_no, current_offset);
                        // unwrap should be safe at this point: We will only reach the ReadState::VFM through ReadState::FileHeader
                        // which always ensures hat the VFM exists.
                        Ok(EncodingState::PreparedData(PreparedData::PreparedVFM(file_encoder.encoded_vfm()?.unwrap())))
                    },
                    ReadState::FileFooter => {
                        self.read_state = ReadState::FileHeader;
                        let encoding_state = EncodingState::PreparedData(PreparedData::PreparedFileHeader(file_encoder.encoded_footer()));
                        match self.virtual_object_source.next() {
                            None => self.current_file_encoder = None,
                            Some(virtual_source) => {
                                let (file_header, vffm) = virtual_source?;
                                let vff = VirtualFileFooter::new(file_header.file_number, vffm.hash_header, vffm.length_of_data, vffm.vfc.clone().into());
                                let vfm = match vffm.vfc {
                                    VirtualFileContent::FileMap(vfm) => Some(vfm),
                                    _ => None
                                };
                                let enc_info = if let Some(encryption_key) = &self.encryption_key {
                                    self.obj_header.encryption_header.as_ref().map(|enc_header| EncryptionInformation::new(
                                        encryption_key.to_vec(), enc_header.algorithm.clone()))
                                } else {
                                    None
                                };
                                self.current_file_encoder = Some(VirtualFileEncoder::new(file_header, vff, vfm, enc_info));
                            }
                        }

                        Ok(encoding_state)
                    }
                }
            }
        }
    }

	/// Returns the encoded footer for this object.
	/// Sets the creation timestamp of the object footer to current system time.
	pub fn get_encoded_footer(&mut self) -> Result<Vec<u8>> {
		self.obj_footer.root_dir_filenumbers = self.virtual_object_source.root_dir_filenumbers().clone();
		let systemtime = OffsetDateTime::from(SystemTime::now()).unix_timestamp() as u64;
		self.obj_footer.creation_timestamp = systemtime;
		if let Some(encryption_key) = &self.encryption_key {
			let encryption_information = EncryptionInformation {
				encryption_key: encryption_key.to_vec(),
				// unwrap should be safe here: there should not an encryption key exists without an encryption header.
				algorithm: self.obj_header.encryption_header.clone().unwrap().algorithm.clone()
			};
	    	self.obj_footer.encrypt_directly(encryption_information)
	    } else {
	    	Ok(self.obj_footer.encode_directly())
	    }
	}

}