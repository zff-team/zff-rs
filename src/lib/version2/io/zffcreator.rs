// - STD
use std::io::{Read, Write, Seek, SeekFrom, Cursor};
use std::path::{PathBuf};
use std::fs::{File, Metadata, OpenOptions, remove_file, read_link, read_dir};
use std::collections::{HashMap, VecDeque};
#[cfg(target_family = "unix")]
use std::os::unix::fs::MetadataExt;

// - internal
use crate::{
	Result,
	HashType,
	HeaderCoding,
	ZffError,
	ZffErrorKind,
	file_extension_next_value,
	DEFAULT_HEADER_VERSION_SEGMENT_HEADER,
	DEFAULT_FOOTER_VERSION_SEGMENT_FOOTER,
	DEFAULT_FOOTER_VERSION_MAIN_FOOTER,
	FILE_EXTENSION_FIRST_VALUE,
	DEFAULT_HEADER_VERSION_FILE_HEADER,
	METADATA_EXT_KEY_DEVID,
	METADATA_EXT_KEY_INODE,
	METADATA_EXT_KEY_MODE,
	METADATA_EXT_KEY_UID,
	METADATA_EXT_KEY_GID,
};
use crate::{
	header::{ObjectHeader, MainHeader, SegmentHeader, FileType, FileHeader, ChunkHeader},
	footer::{SegmentFooter, MainFooter},
	version2::{
		object::{PhysicalObjectEncoder, LogicalObjectEncoder},
	}
};

// - external
use ed25519_dalek::{Keypair};
use time::{OffsetDateTime};

/// TODO: Docs
pub struct ZffCreatorPhysical<R: Read> {
	object_encoder: PhysicalObjectEncoder<R>,
	output_filenpath: String,
	current_segment_no: u64,
	written_object_header: bool,
	last_accepted_segment_filepath: PathBuf,
	description_notes: Option<String>,
	object_header_segment_numbers: HashMap<u64, u64>,
	object_footer_segment_numbers: HashMap<u64, u64>,
}

impl<R: Read> ZffCreatorPhysical<R> {
	pub fn new<O: Into<String>>(
		object_header: ObjectHeader,
		input_data: R,
		hash_types: Vec<HashType>,
		encryption_key: Option<Vec<u8>>,
		signature_key: Option<Keypair>,
		main_header: MainHeader,
		header_encryption: bool,
		description_notes: Option<String>,
		output_filenpath: O) -> Result<ZffCreatorPhysical<R>> {
		let initial_chunk_number = 1;
		Ok(Self {
			object_encoder: PhysicalObjectEncoder::new(
				object_header,
				input_data,
				hash_types,
				encryption_key,
				signature_key,
				main_header,
				initial_chunk_number,
				header_encryption)?, // the first chunk number for the first object should always be 1.
			output_filenpath: output_filenpath.into(),
			current_segment_no: 1, // initial segment number should always be 1.
			written_object_header: false,
			last_accepted_segment_filepath: PathBuf::new(),
			description_notes: description_notes,
			object_header_segment_numbers: HashMap::new(),
			object_footer_segment_numbers: HashMap::new(),
		})
	}

	pub fn generate_files(&mut self) -> Result<()> {
		let mut first_segment_filename = PathBuf::from(&self.output_filenpath);
	    let mut file_extension = String::from(FILE_EXTENSION_FIRST_VALUE);
	    first_segment_filename.set_extension(&file_extension);
	    self.last_accepted_segment_filepath = first_segment_filename.clone();
	    let mut output_file = File::create(&first_segment_filename)?;
		let encoded_main_header = self.object_encoder.main_header().encode_directly();

	    output_file.write(&encoded_main_header)?;
	    let mut main_footer_start_offset = self.write_next_segment(&mut output_file, encoded_main_header.len() as u64)? +
	    								   encoded_main_header.len() as u64;

	    loop {
	    	self.current_segment_no += 1;
	    	file_extension = file_extension_next_value(&file_extension)?;
	    	let mut segment_filename = PathBuf::from(&self.output_filenpath);
	    	segment_filename.set_extension(&file_extension);
	    	let mut output_file = File::create(&segment_filename)?;
	    	main_footer_start_offset = match self.write_next_segment(&mut output_file, 0) {
	    		Ok(written_bytes) => written_bytes,
	    		Err(e) => match e.get_kind() {
	    			ZffErrorKind::ReadEOF => {
	    				remove_file(segment_filename)?;
	    				break;
	    			},
	    			_ => return Err(e),
	    		},
	    	};
	    	self.last_accepted_segment_filepath = segment_filename.clone();
	    }
	    let main_footer = MainFooter::new(DEFAULT_FOOTER_VERSION_MAIN_FOOTER, self.current_segment_no-1, self.object_header_segment_numbers.clone(), self.object_footer_segment_numbers.clone(), self.description_notes.clone(), main_footer_start_offset);
	    let mut output_file = OpenOptions::new().write(true).append(true).open(&self.last_accepted_segment_filepath)?;
	    //TODO: Handle encrypted main footer.
	    output_file.write(&main_footer.encode_directly())?;

	    Ok(())
	}

	fn write_next_segment<W: Write + Seek>(
		&mut self,
		output: &mut W,
		seek_value: u64, // The seek value is a value of bytes you need to skip (e.g. the main_header, the object_header, ...)
		) -> Result<u64> // returns written_bytes
	{
		output.seek(SeekFrom::Start(seek_value))?;
		let mut written_bytes: u64 = 0;
		let target_chunk_size = self.object_encoder.main_header().chunk_size();
		let target_segment_size = self.object_encoder.main_header().segment_size();
		
		//prepare segment header
		let segment_header = SegmentHeader::new(
			DEFAULT_HEADER_VERSION_SEGMENT_HEADER,
			self.object_encoder.main_header().unique_identifier(),
			self.current_segment_no);

		//check if the segment size is to small
		if (seek_value as usize +
			&segment_header.encode_directly().len() +
			self.object_encoder.get_encoded_header().len() +
			target_chunk_size) > self.object_encoder.main_header().segment_size() as usize {
	        
	        return Err(ZffError::new(ZffErrorKind::SegmentSizeToSmall, ""));
	    };

		//write segment header
		written_bytes += output.write(&segment_header.encode_directly())? as u64;

		//prepare segment footer
		let mut segment_footer = SegmentFooter::new_empty(DEFAULT_FOOTER_VERSION_SEGMENT_FOOTER);	
		
		//write the object header
		if !self.written_object_header {
			self.object_header_segment_numbers.insert(self.object_encoder.obj_number(), self.current_segment_no);
			segment_footer.add_object_header_offset(self.object_encoder.obj_number(), seek_value + written_bytes);
			written_bytes += output.write(&self.object_encoder.get_encoded_header())? as u64;
			self.written_object_header = true;
		};

		// read chunks and write them into the Writer.
		loop {
			if (written_bytes +
				segment_footer.encode_directly().len() as u64 +
				target_chunk_size as u64) > target_segment_size-seek_value as u64 {
				
				if written_bytes == segment_header.encode_directly().len() as u64 {
					return Err(ZffError::new(ZffErrorKind::ReadEOF, ""));
				} else {
					break;
				}
			};
			let chunk_offset = seek_value + written_bytes;
			let current_chunk_number = self.object_encoder.current_chunk_number();
			let chunk = match self.object_encoder.get_next_chunk() {
				Ok(data) => data,
				Err(e) => match e.get_kind() {
					ZffErrorKind::ReadEOF => {
						if written_bytes == segment_header.encode_directly().len() as u64 {
							return Err(e);
						} else {
							//write the appropriate object footer and break the loop
							self.object_footer_segment_numbers.insert(self.object_encoder.obj_number(), self.current_segment_no);
							segment_footer.add_object_footer_offset(self.object_encoder.obj_number(), seek_value + written_bytes);
							written_bytes += output.write(&self.object_encoder.get_encoded_footer())? as u64;
							break;
						}
					},
					ZffErrorKind::InterruptedInputStream => {
						break;
					},
					_ => return Err(e),
				},
			};
			written_bytes += output.write(&chunk)? as u64;
			segment_footer.add_chunk_offset(current_chunk_number, chunk_offset);
		}

		// finish the segment footer and write the encoded footer into the Writer.
		segment_footer.set_footer_offset(seek_value + written_bytes);
		segment_footer.set_length_of_segment(seek_value + written_bytes + segment_footer.encode_directly().len() as u64);
		written_bytes += output.write(&segment_footer.encode_directly())? as u64;
		Ok(written_bytes)
	}
}

/// TODO: Docs
pub struct ZffCreatorLogical {
	object_encoder: LogicalObjectEncoder,
	output_filenpath: String,
	current_segment_no: u64,
	written_object_header: bool,
	last_accepted_segment_filepath: PathBuf,
	unaccessable_files: Vec<String>,
	description_notes: Option<String>,
	object_header_segment_numbers: HashMap<u64, u64>,
	object_footer_segment_numbers: HashMap<u64, u64>,
}

impl ZffCreatorLogical {
	pub fn new<O: Into<String>>(
		object_header: ObjectHeader,
		input_files: Vec<PathBuf>,
		hash_types: Vec<HashType>,
		encryption_key: Option<Vec<u8>>,
		signature_key: Option<Keypair>,
		main_header: MainHeader,
		header_encryption: bool,
		description_notes: Option<String>,
		output_filenpath: O)-> Result<ZffCreatorLogical> {
		let initial_chunk_number = 1;
		let mut current_file_number = 1;
		let mut parent_file_number = 0;
		let mut hardlink_map = HashMap::new();
		let mut unaccessable_files = Vec::new();
		let mut directories_to_traversal = VecDeque::new(); //<directory_path, parent_file_number>
		let mut files = Vec::new();
		let mut symlink_real_paths = HashMap::new();

		for path in input_files {
			let metadata = std::fs::symlink_metadata(&path)?;
			let file = match File::open(&path) {
				Ok(f) => f,
				Err(_) => {
					if !metadata.is_symlink() {
						unaccessable_files.push(path.to_string_lossy().to_string());
					};
					continue;
				},
			};

			// - files in root tree
			if metadata.file_type().is_dir() {
				directories_to_traversal.push_back((path, parent_file_number)); // parent_file_number of root directory is always 0.
			} else {
				if metadata.file_type().is_symlink() {
					match read_link(&path) {
						Ok(symlink_real) => symlink_real_paths.insert(current_file_number, symlink_real),
						Err(_) => symlink_real_paths.insert(current_file_number, PathBuf::from("")),
					};
				}
				let file_header = match get_file_header(&metadata, &file, &path, current_file_number, parent_file_number) {
					Ok(file_header) => file_header,
					Err(_) => continue, //TODO: check if there should be a real error handling possible.
				};
				add_to_hardlink_map(&mut hardlink_map, &metadata, current_file_number);
				current_file_number += 1;
				files.push((file, file_header));
			}
		}

		// - files in subfolders
		loop {
			// - folder
			let mut inner_dir_elements = VecDeque::new();
			let (current_dir, dir_parent_file_number) = match directories_to_traversal.pop_front() {
				Some((current_dir, dir_parent_file_number)) => (current_dir, dir_parent_file_number),
				None => break,
			};
			
			let element_iterator = match read_dir(&current_dir) {
				Ok(iterator) => iterator,
				Err(_) => {
					unaccessable_files.push(current_dir.to_string_lossy().to_string());
					continue;
				}
			};

			let file = match File::open(&current_dir) {
				Ok(f) => f,
				Err(_) => {
					unaccessable_files.push(current_dir.to_string_lossy().to_string());
					continue;
				},
			};

			parent_file_number = current_file_number;
			let metadata = file.metadata()?;
			let file_header = match get_file_header(&metadata, &file, &current_dir, current_file_number, dir_parent_file_number) {
				Ok(file_header) => file_header,
				Err(_) => continue, //TODO: check if there should be a real error handling possible.
			};
			add_to_hardlink_map(&mut hardlink_map, &metadata, current_file_number);
			current_file_number += 1;
			files.push((file, file_header));

			// files in current folder
			for inner_element in element_iterator {
				let inner_element = match inner_element {
					Ok(element) => element,
					Err(e) => {
						unaccessable_files.push(e.to_string());
						continue;
					}
				};
				let file = match File::open(&inner_element.path()) {
					Ok(f) => f,
					Err(_) => {
						unaccessable_files.push(inner_element.path().to_string_lossy().to_string());
						continue;
					},
				};
				let metadata = file.metadata()?;
				if metadata.file_type().is_dir() {
					inner_dir_elements.push_back((inner_element.path(), parent_file_number));
				} else {
					match read_link(inner_element.path()) {
						Ok(symlink_real) => symlink_real_paths.insert(current_file_number, symlink_real),
						Err(_) => symlink_real_paths.insert(current_file_number, PathBuf::from("")),
					};
					let path = inner_element.path().clone();
					let file_header = match get_file_header(&metadata, &file, &path, current_file_number, parent_file_number) {
						Ok(file_header) => file_header,
						Err(_) => continue, //TODO: check if there should be a real error handling possible.
					};
					add_to_hardlink_map(&mut hardlink_map, &metadata, current_file_number);
					current_file_number += 1;
					files.push((file, file_header));
				}
				directories_to_traversal.append(&mut inner_dir_elements);
			}
		}
		let signature_key_bytes = match signature_key {
			Some(keypair) => Some(keypair.to_bytes().to_vec()),
			None => None
		};
		let logical_object_encoder = LogicalObjectEncoder::new(
			object_header,
			files,
			hash_types,
			encryption_key,
			signature_key_bytes,
			main_header,
			symlink_real_paths,
			hardlink_map,
			initial_chunk_number,
			header_encryption)?; // 1 is always the initial chunk number.
		Ok(Self {
			object_encoder: logical_object_encoder,
			output_filenpath: output_filenpath.into(),
			current_segment_no: 1, // 1 is always the initial segment no.
			written_object_header: false,
			last_accepted_segment_filepath: PathBuf::new(),
			unaccessable_files: unaccessable_files,
			description_notes: description_notes,
			object_header_segment_numbers: HashMap::new(),
			object_footer_segment_numbers: HashMap::new(),
		})
	}

	pub fn generate_files(&mut self) -> Result<()> {

		let mut first_segment_filename = PathBuf::from(&self.output_filenpath);
	    let mut file_extension = String::from(FILE_EXTENSION_FIRST_VALUE);
	    first_segment_filename.set_extension(&file_extension);
	    self.last_accepted_segment_filepath = first_segment_filename.clone();
	    let mut output_file = File::create(&first_segment_filename)?;

		let encoded_main_header = self.object_encoder.main_header().encode_directly();

	    output_file.write(&encoded_main_header)?;
	    let mut main_footer_start_offset = self.write_next_segment(&mut output_file, encoded_main_header.len() as u64)? +
	    								   encoded_main_header.len() as u64;

	    loop {
	    	self.current_segment_no += 1;
	    	file_extension = file_extension_next_value(&file_extension)?;
	    	let mut segment_filename = PathBuf::from(&self.output_filenpath);
	    	segment_filename.set_extension(&file_extension);
	    	let mut output_file = File::create(&segment_filename)?;
	    	main_footer_start_offset = match self.write_next_segment(&mut output_file, 0) {
	    		Ok(written_bytes) => written_bytes,
	    		Err(e) => match e.get_kind() {
	    			ZffErrorKind::ReadEOF => {
	    				remove_file(segment_filename)?;
	    				break;
	    			},
	    			_ => return Err(e),
	    		},
	    	};
	    	self.last_accepted_segment_filepath = segment_filename.clone();
	    }

	    let main_footer = MainFooter::new(DEFAULT_FOOTER_VERSION_MAIN_FOOTER, self.current_segment_no-1, self.object_header_segment_numbers.clone(), self.object_footer_segment_numbers.clone(), self.description_notes.clone(), main_footer_start_offset);
	    let mut output_file = OpenOptions::new().write(true).append(true).open(&self.last_accepted_segment_filepath)?;
	    //TODO: Handle encrypted main footer.
	    output_file.write(&main_footer.encode_directly())?;

	    Ok(())
	}

	pub fn unaccessable_files(&self) -> &Vec<String> {
		&self.unaccessable_files
	}

	fn write_next_segment<W: Write + Seek>(
		&mut self,
		output: &mut W,
		seek_value: u64, // The seek value is a value of bytes you need to skip (e.g. the main_header, the object_header, ...)
		) -> Result<u64> // returns written_bytes
	{
		output.seek(SeekFrom::Start(seek_value))?;
		let mut written_bytes: u64 = 0;
		let target_chunk_size = self.object_encoder.main_header().chunk_size();
		let target_segment_size = self.object_encoder.main_header().segment_size();
		
		//prepare segment header
		let segment_header = SegmentHeader::new(
			DEFAULT_HEADER_VERSION_SEGMENT_HEADER,
			self.object_encoder.main_header().unique_identifier(),
			self.current_segment_no);

		//check if the segment size is to small
		if (seek_value as usize +
			&segment_header.encode_directly().len() +
			self.object_encoder.get_encoded_header().len() +
			target_chunk_size) > self.object_encoder.main_header().segment_size() as usize {
	        
	        return Err(ZffError::new(ZffErrorKind::SegmentSizeToSmall, ""));
	    };

		//write segment header
		written_bytes += output.write(&segment_header.encode_directly())? as u64;

		//prepare segment footer
		let mut segment_footer = SegmentFooter::new_empty(DEFAULT_FOOTER_VERSION_SEGMENT_FOOTER);	
		
		//write the object header
		if !self.written_object_header {
			self.object_header_segment_numbers.insert(self.object_encoder.obj_number(), self.current_segment_no);
			segment_footer.add_object_header_offset(self.object_encoder.obj_number(), written_bytes+seek_value);
			written_bytes += output.write(&self.object_encoder.get_encoded_header())? as u64;
			self.written_object_header = true;
		};

		// read chunks and write them into the Writer.
		loop {
			if (written_bytes +
				segment_footer.encode_directly().len() as u64 +
				target_chunk_size as u64) > target_segment_size-seek_value as u64 {
				
				if written_bytes == segment_header.encode_directly().len() as u64 {
					return Err(ZffError::new(ZffErrorKind::ReadEOF, ""));
				} else {
					break;
				}
			};
			let current_offset = seek_value + written_bytes;
			let current_chunk_number = self.object_encoder.current_chunk_number();
			let data = match self.object_encoder.get_next_data(current_offset, self.current_segment_no) {
				Ok(data) => data,
				Err(e) => match e.get_kind() {
					ZffErrorKind::ReadEOF => {
						if written_bytes == segment_header.encode_directly().len() as u64 {
							return Err(e);
						} else {
							//write the appropriate object footer and break the loop
							self.object_footer_segment_numbers.insert(self.object_encoder.obj_number(), self.current_segment_no);
							segment_footer.add_object_footer_offset(self.object_encoder.obj_number(), written_bytes+seek_value);
							written_bytes += output.write(&self.object_encoder.get_encoded_footer())? as u64;
							break;
						}
					},
					ZffErrorKind::InterruptedInputStream => {
						break;
					},
					_ => return Err(e),
				},
			};
			written_bytes += output.write(&data)? as u64;

			let mut data_cursor = Cursor::new(&data);
			if ChunkHeader::check_identifier(&mut data_cursor) {
				segment_footer.add_chunk_offset(current_chunk_number, current_offset);
			};
		}

		// finish the segment footer and write the encoded footer into the Writer.
		segment_footer.set_footer_offset(seek_value + written_bytes);
		segment_footer.set_length_of_segment(seek_value + written_bytes + segment_footer.encode_directly().len() as u64);
		written_bytes += output.write(&segment_footer.encode_directly())? as u64;
		Ok(written_bytes)
	}
}

//TODO: target_os = "windows"
//TODO: target_os = "macos"
#[cfg(target_os = "linux")]
fn get_metadata_ext(file: &File) -> Result<HashMap<String, String>> {
	let metadata = file.metadata()?;
	let mut metadata_ext = HashMap::new();

	//dev-id
	metadata_ext.insert(METADATA_EXT_KEY_DEVID.into(), metadata.dev().to_string());
	// inode
	metadata_ext.insert(METADATA_EXT_KEY_INODE.into(), metadata.ino().to_string());
	// mode
	metadata_ext.insert(METADATA_EXT_KEY_MODE.into(), metadata.mode().to_string());
	// uid
	metadata_ext.insert(METADATA_EXT_KEY_UID.into(), metadata.uid().to_string());
	// gid
	metadata_ext.insert(METADATA_EXT_KEY_GID.into(), metadata.gid().to_string());

	Ok(metadata_ext)
}

fn get_time_from_metadata(metadata: &Metadata) -> HashMap<&str, u64> {
	let mut timestamps = HashMap::new();

	let atime = match metadata.accessed() {
		Ok(atime) => OffsetDateTime::from(atime).unix_timestamp() as u64,
		Err(_) => 0
	};
	let mtime = match metadata.modified() {
		Ok(mtime) => OffsetDateTime::from(mtime).unix_timestamp() as u64,
		Err(_) => 0
	};
	#[cfg(target_family = "windows")]
	let ctime = match metadata.modified() {
		Ok(ctime) => OffsetDateTime::from(ctime).unix_timestamp() as u64,
		Err(_) => 0
	};
	#[cfg(target_family = "unix")]
	let ctime = metadata.ctime() as u64;

	let btime = match metadata.created() {
		Ok(btime) => OffsetDateTime::from(btime).unix_timestamp() as u64,
		Err(_) => 0
	};

	timestamps.insert("atime", atime);
	timestamps.insert("mtime", mtime);
	timestamps.insert("ctime", ctime);
	timestamps.insert("btime", btime);

	timestamps
}

fn get_file_header(metadata: &Metadata, file: &File, path: &PathBuf, current_file_number: u64, parent_file_number: u64) -> Result<FileHeader> {
	let filetype = if metadata.file_type().is_dir() {
		FileType::Directory
	} else if metadata.file_type().is_file() {
		FileType::File
	} else if metadata.file_type().is_symlink() {
		FileType::Symlink
	} else {
		return Err(ZffError::new(ZffErrorKind::UnknownFileType, ""));
	};

	let filename = match path.file_name() {
		Some(filename) => filename.to_string_lossy(),
		None => path.to_string_lossy(),
	};
	let timestamps = get_time_from_metadata(&metadata);
	let atime = timestamps.get("atime").unwrap();
	let mtime = timestamps.get("mtime").unwrap();
	let ctime = timestamps.get("ctime").unwrap();
	let btime = timestamps.get("btime").unwrap();

	let metadata_ext = get_metadata_ext(&file)?;

	let file_header = FileHeader::new(
					DEFAULT_HEADER_VERSION_FILE_HEADER,
					current_file_number,
					filetype,
					filename,
					parent_file_number,
					*atime,
					*mtime,
					*ctime,
					*btime,
					metadata_ext);
	Ok(file_header)
}

// returns ...
// ... None, if there is no other hardlink available to this file or if there is another hardlink available to this file, but this is the first of the hardlinked files, you've read.
// ... Some(filenumber), if there is another hardlink available and already was read.
#[cfg(target_family = "unix")]
fn add_to_hardlink_map(hardlink_map: &mut HashMap<u64, HashMap<u64, u64>>, metadata: &Metadata, filenumber: u64) -> Option<u64> {
	if metadata.nlink() > 1 {
		match hardlink_map.get_mut(&metadata.dev()) {
			Some(inner_map) => match inner_map.get_mut(&metadata.ino()) {
				Some(fno) => return Some(*fno),
				None => {
					inner_map.insert(metadata.ino(), filenumber);
					return None
				},
			},
			None => {
				hardlink_map.insert(metadata.dev(), HashMap::new());
				hardlink_map.get_mut(&metadata.dev()).unwrap().insert(metadata.ino(), filenumber);
				return None;
			},
		}
	}
	None
}