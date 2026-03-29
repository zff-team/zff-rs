// - Parent
use super::*;

/// A reader which contains the appropriate metadata of a logical object 
/// (e.g. the appropriate [ObjectHeader](crate::header::ObjectHeader) and [ObjectFooter](crate::footer::ObjectFooter)).
#[derive(Debug)]
pub(crate) struct ZffObjectReaderVirtualLogical<R: Read + Seek> {
	metadata: ArcZffReaderMetadata<R>,
	object_header: ObjectHeader,
	object_footer: ObjectFooterVirtualLogical,
}

impl<R: Read + Seek> ZffObjectReaderVirtualLogical<R> {
    /// creates a new [ZffObjectReaderVirtual] with the given metadata.
	pub fn with_data(object_no: u64, metadata: ArcZffReaderMetadata<R>) -> Result<Self> {
        todo!()
    }

    pub(crate) fn filemetadata(&self) -> Result<&FileMetadata> {
        todo!()
    }

    pub fn current_fileheader(&self) -> Result<FileHeader> {
        todo!()
    }

    pub fn current_filefooter(&self) -> Result<FileFooter> {
        todo!()
    }

    /// Returns a reference of the appropriate [ObjectHeader](crate::header::ObjectHeader).
	pub(crate) fn object_header_ref(&self) -> &ObjectHeader {
		&self.object_header
	}

    /// Returns the appropriate [ObjectFooter](crate::footer::ObjectFooter).
	pub(crate) fn object_footer(&self) -> ObjectFooter {
		ObjectFooter::VirtualLogical(self.object_footer.clone())
	}
}

impl<R: Read + Seek> Read for ZffObjectReaderVirtualLogical<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        todo!()
    }
}

impl<R: Read + Seek> Seek for ZffObjectReaderVirtualLogical<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        todo!()
    }
}