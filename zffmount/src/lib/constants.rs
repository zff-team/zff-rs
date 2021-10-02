// - STD
use std::time::{Duration, UNIX_EPOCH};

// - external
use fuser::{FileAttr, FileType};

pub const PROGRAM_NAME: &str = env!("CARGO_BIN_NAME");
pub const PROGRAM_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PROGRAM_AUTHOR: &str = env!("CARGO_PKG_AUTHORS");
pub const PROGRAM_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

// clap
// - args
pub const CLAP_ARG_NAME_INPUT_FILE: &str = "INPUT_FILE";
pub const CLAP_ARG_HELP_INPUT_FILE: &str = "The input file. This should be your device to dump.";
pub const CLAP_ARG_SHORT_INPUT_FILE: &str = "i";
pub const CLAP_ARG_LONG_INPUT_FILE: &str = "inputfile";

pub const CLAP_ARG_NAME_MOUNT_DIR: &str = "MOUNT_DIR";
pub const CLAP_ARG_HELP_MOUNT_DIR: &str = "Directory, where the file(s) are be mounted to.";
pub const CLAP_ARG_SHORT_MOUNT_DIR: &str = "m";
pub const CLAP_ARG_LONG_MOUNT_DIR: &str = "mount-dir";

// - errrors
pub const ERROR_OPEN_INPUT_FILE: &str = "An errror occurred while trying to open the input file: ";
pub const ERROR_SERIALIZE_METADATA: &str = "Could not serialize the metadata of the main header.";
pub const ERROR_CREATE_ZFFFS: &str = "Error occurred while trying to create the Zffs-FS: ";
pub const ERROR_MOUNT_ZFFFS: &str = "Error occurred while trying to mount the file(s): ";
pub const ERROR_ZFFFS_READ_SEEK: &str = "Could not read data at given offset.";
pub const ERROR_ZFFFS_READ_READ: &str = "An I/O error has occurred: ";

pub const EXIT_STATUS_ERROR: i32 = 1;
pub const EXIT_STATUS_SUCCESS: i32 = 0;

// fuser constants
pub const TTL: Duration = Duration::from_secs(1); // 1 second
pub const DEFAULT_BLOCKSIZE: u32 = 512;
pub const FILESYSTEM_NAME: &str = "ZffFS";

pub const DEFAULT_DIR_INODE: u64 = 1;

// metadata file
pub const DEFAULT_METADATA_NAME: &'static str = "metadata.toml";
pub const DEFAULT_METADATA_INODE: u64 = 2;
pub const DEFAULT_METADATA_FILE_PERMISSION: u16 = 0o644;
pub const DEFAULT_METADATA_HARDLINKS: u32 = 1;

// zff image file
pub const DEFAULT_ZFF_IMAGE_NAME: &'static str = "zff_image.dd";
pub const DEFAULT_ZFF_IMAGE_INODE: u64 = 3;
pub const DEFAULT_ZFF_IMAGE_FILE_PERMISSION: u16 = 0o644;
pub const DEFAULT_ZFF_IMAGE_HARDLINKS: u32 = 1;


pub const DEFAULT_DIR_ATTR: FileAttr = FileAttr {
    ino: DEFAULT_DIR_INODE,
    size: 0,
    blocks: 0,
    atime: UNIX_EPOCH, // 1970-01-01 00:00:00
    mtime: UNIX_EPOCH,
    ctime: UNIX_EPOCH,
    crtime: UNIX_EPOCH,
    kind: FileType::Directory,
    perm: 0o755,
    nlink: 2,
    uid: 501,
    gid: 20,
    rdev: 0,
    flags: 0,
    blksize: 512,
};
pub const DEFAULT_ENTRY_GENERATION: u64 = 0;