// - internal
use crate::prelude::*;

// - external
use zeroize::Zeroize;

/// Encodes the a virtual file.
pub struct VirtualFileEncoder {
    /// The appropriate [FileHeader].
	pub file_header: FileHeader,
    /// The appropriate [VirtualFileFooter].
    pub file_footer: VirtualFileFooter,
    /// The resolved virtual file map for regular virtual files, in case of a virtual regular file.
    pub vfm: Option<VirtualFileMap>,
    /// optional encryption information, to encrypt the data with the given key and algorithm (if the appropriate
	/// object is encrypted).
	encryption_information: Option<EncryptionInformation>,
}

impl Drop for VirtualFileEncoder {
	fn drop(&mut self) {
		self.encryption_information.zeroize();
	}
}

impl VirtualFileEncoder {
    /// Creates a new [`VirtualFileEncoder`] from the header, footer, optional
    /// virtual file map, and optional encryption information.
    pub fn new(
		file_header: FileHeader, 
		file_footer: VirtualFileFooter, 
		vfm: Option<VirtualFileMap>,
		encryption_information: Option<EncryptionInformation>) -> Self {
        Self {
            file_header,
            file_footer,
            vfm,
            encryption_information,
        }
    }

    /// Returns a reference of the appropriate file header
	pub fn file_header_ref(&self) -> &FileHeader {
		&self.file_header
	}

    /// Returns the encoded [`FileHeader`].
	pub fn encoded_header(&self) -> Vec<u8> {
		if let Some(enc_info) = &self.encryption_information {
			//unwrap should be safe here, because we have already testet this before.
	    	self.file_header.encode_encrypted_header_directly(enc_info).unwrap()
	    } else {
	    	self.file_header.encode_directly()
	    }
	}

	/// Returns the encoded [`VirtualFileMap`], if this virtual file has one.
	///
	/// # Error
	/// Returns an error if encoding the virtual file map with the configured
	/// encryption settings fails.
	pub fn encoded_vfm(&self) -> Result<Option<Vec<u8>>> {
		if let Some(vfm) = &self.vfm {
			if let Some(enc_info) = &self.encryption_information {
				Ok(Some(vfm.encode_encrypted_footer(&enc_info.encryption_key, &enc_info.algorithm)?))
			} else {
				Ok(Some(vfm.encode_directly()))
			}
		} else {
			Ok(None)
		}
	}

    /// Returns the appropriate encoded [VirtualFileFooter].
	pub fn encoded_footer(&self) -> Vec<u8> {
		if let Some(enc_info) = &self.encryption_information {
            //unwrap should be safe here, because we have already testet this before.
	    	self.file_footer.encode_encrypted_header_directly(enc_info).unwrap()
	    } else {
	    	self.file_footer.encode_directly()
	    }
	}
}
