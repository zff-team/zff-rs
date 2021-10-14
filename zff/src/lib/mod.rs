#![forbid(unsafe_code)]
#![deny(missing_docs, rust_2018_idioms)]

//! This crate provides the reference implementation of the forensic file format ZFF.\
//! ZFF is a new file format for forensic images, as an alternative to EWF and AFF.\
//! ZFF is focused on speed and security.
//! If you want to learn more about ZFF, visit <https://github.com/ph0llux/zff>.
//! # Create a zff file
//! To create a zff file, you can easily use the [ZffWriter](crate::ZffWriter)-struct.
//! To create a [ZffWriter](crate::ZffWriter), you also need a [MainHeader](crate::header::MainHeader),
//! to create a [MainHeader](crate::header::MainHeader), you need a lot of other header and so on.
//! This documentation will show you a very little minimal example to create all the needed stuff.
//!
//! ##### building a CompressionHeader
//! We will start to set the compression abilities by building a [CompressionHeader](crate::header::CompressionHeader):
//! ```
//! use zff::header::*;
//! use zff::{
//! 	CompressionAlgorithm,
//!		DEFAULT_HEADER_VERSION_COMPRESSION_HEADER,	
//! };
//! 
//! fn build_compression_header() -> CompressionHeader {
//!		let algorithm = CompressionAlgorithm::Zstd;
//! 	let compression_level = 3;
//! 	let compression_header = CompressionHeader::new(DEFAULT_HEADER_VERSION_COMPRESSION_HEADER, algorithm, compression_level);
//! 	compression_header
//! }
//! ```
//! ##### building a DescriptionHeader
//! Next, we will set all the describing information about our image file(s) by building a [DescriptionHeader](crate::header::DescriptionHeader):
//! ```
//! use std::time::{SystemTime, UNIX_EPOCH};
//! use zff::header::*;
//! use zff::{
//! 	DEFAULT_HEADER_VERSION_DESCRIPTION_HEADER
//! };
//! 
//! fn build_description_header() -> DescriptionHeader {
//! 	let examiner = "ph0llux";
//! 	let start_date = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
//! 	
//! 	let mut description_header = DescriptionHeader::new_empty(DEFAULT_HEADER_VERSION_DESCRIPTION_HEADER);
//! 	description_header.set_examiner_name(examiner);
//! 	description_header.set_acquisition_start(start_date);
//! 	description_header
//! }
//! ```
//! ##### building a HashHeader
//! The last "subheader" of the MainHeader, we will build in this little guide is the [HashHeader](crate::header::HashHeader),
//! which contains several information about the used hash algorithms in this image.
//! ```
//! use zff::header::*;
//! use zff::{
//!		HashType,
//! 	DEFAULT_HEADER_VERSION_HASH_VALUE_HEADER,
//! 	DEFAULT_HEADER_VERSION_HASH_HEADER
//! };
//! 
//! fn build_hash_header() -> HashHeader {
//! 	let mut hash_values = Vec::new();
//! 	hash_values.push(HashValue::new_empty(DEFAULT_HEADER_VERSION_HASH_VALUE_HEADER, HashType::Blake2b512));
//! 	hash_values.push(HashValue::new_empty(DEFAULT_HEADER_VERSION_HASH_VALUE_HEADER, HashType::SHA256));
//! 	
//! 	let hash_header = HashHeader::new(DEFAULT_HEADER_VERSION_HASH_HEADER, hash_values);
//! 	hash_header
//! }
//! ```
//! ##### building the MainHeader
//! With the previous built [CompressionHeader](crate::header::CompressionHeader),
//! [DescriptionHeader](crate::header::DescriptionHeader) and [HashHeader](crate::header::HashHeader), and some
//! additional information we will now generate a [MainHeader](crate::header::MainHeader).
//! ```no_run
//! use zff::header::*;
//! use zff::{
//! 	DEFAULT_HEADER_VERSION_MAIN_HEADER,
//! 	DEFAULT_CHUNK_SIZE,
//! };
//! 
//! fn build_main_header() -> MainHeader {
//! 	let version = DEFAULT_HEADER_VERSION_MAIN_HEADER;
//! 	let ch = build_compression_header();
//! 	let dh = build_description_header();
//! 	let hh = build_hash_header();
//! 	let chunk_size = DEFAULT_CHUNK_SIZE;
//! 	let sig_flag = 0; // we trust everything in this world and won't sign the image file. ;)
//! 	let seg_size = u64::MAX; // we won't split the image into segments.
//!		let unique_identifier = 1;
//! 	let len_of_data = 0; //initial value, will be overwritten automatically by ZffWriter
//! 
//! 	let main_header = MainHeader::new(
//! 									version,
//!										None, //we won't set an encryption header yet.
//! 									ch,
//! 									dh,
//! 									hh,
//! 									chunk_size,
//! 									sig_flag,
//! 									seg_size,
//! 									unique_identifier,
//! 									len_of_data);
//! 	main_header
//! }
//! ```
//! ##### building the ZffWriter and write data to files
//! In the last step, we will create a [ZffWriter](crate::ZffWriter) and dump the input data to the output file(s):
//! ```no_run
//! use std::fs::File;
//! use zff::{Result, ZffWriter};
//! 
//! fn main() -> Result<()> {
//! 	let main_header = build_main_header();
//! 	let input_file = File::open("/tmp/myTestfile.dd")?; //could also be e.g. '/dev/sda'.
//! 	
//! 	//this is some special: you will only give the name-scheme of the output file(s). In this example, the name-scheme is
//! 	// '/tmp/zff_output_file', so the segments of the image will be generated and the appropriate
//! 	// file extension will be added automatically; in this example to '/tmp/zff_output_file.z01'.
//! 	let output_filename_scheme = "/tmp/zff_output_file";
//! 
//! 	// We pass the following information to the ZffWriter: The MainHeader, the input file, the output filename scheme,
//! 	// None for "No signature key", None for "No encryption key" and false for "No, we won't want to encrypt the header".
//! 	let zff_writer = ZffWriter::new(main_header, input_file, output_filename_scheme, None, None, false);
//! 	
//! 	//create/write the image file(s)
//! 	zff_writer.generate_files()
//! }
//! ```

// - modules
mod error;
mod constants;
mod traits;
mod compression;
mod encryption;
mod file_extension;
mod io;
mod hashing;
mod signatures;
mod segment;
pub mod header;
pub mod footer;

// - re-exports
pub use error::*;
pub use constants::*;
pub use traits::*;
pub use compression::*;
pub use encryption::*;
pub use file_extension::*;
pub use io::*;
pub use hashing::*;
pub use signatures::*;
pub use segment::*;

// - types
/// Result for std::result::Result<T, ZffError>.
pub type Result<T> = std::result::Result<T, ZffError>;