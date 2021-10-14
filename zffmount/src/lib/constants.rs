// - STD
use std::time::{Duration, UNIX_EPOCH};

// - external
use fuser::{FileAttr, FileType};

pub(crate) const PROGRAM_NAME: &str = env!("CARGO_BIN_NAME");
pub(crate) const PROGRAM_VERSION: &str = env!("CARGO_PKG_VERSION");
pub(crate) const PROGRAM_AUTHOR: &str = env!("CARGO_PKG_AUTHORS");
pub(crate) const PROGRAM_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

// clap
// - args
pub(crate) const CLAP_ARG_NAME_INPUT_FILE: &str = "INPUT_FILE";
pub(crate) const CLAP_ARG_HELP_INPUT_FILE: &str = "The input file. This should be your device to dump.";
pub(crate) const CLAP_ARG_SHORT_INPUT_FILE: &str = "i";
pub(crate) const CLAP_ARG_LONG_INPUT_FILE: &str = "inputfile";

pub(crate) const CLAP_ARG_NAME_MOUNT_DIR: &str = "MOUNT_DIR";
pub(crate) const CLAP_ARG_HELP_MOUNT_DIR: &str = "Directory, where the file(s) are be mounted to.";
pub(crate) const CLAP_ARG_SHORT_MOUNT_DIR: &str = "m";
pub(crate) const CLAP_ARG_LONG_MOUNT_DIR: &str = "mount-dir";

pub(crate) const CLAP_ARG_NAME_PASSWORD: &str = "PASSWORD";
pub(crate) const CLAP_ARG_HELP_PASSWORD: &str = "The password to decrypt an encrypted zff file.";
pub(crate) const CLAP_ARG_SHORT_PASSWORD: &str = "p";
pub(crate) const CLAP_ARG_LONG_PASSWORD: &str = "password";

// - errors
pub(crate) const ERROR_OPEN_INPUT_FILE: &str = "An error occurred while trying to open the input file: ";
pub(crate) const ERROR_SERIALIZE_METADATA: &str = "Could not serialize the metadata of the main header.";
pub(crate) const ERROR_CREATE_ZFFFS: &str = "Error occurred while trying to create the Zffs-FS: ";
pub(crate) const ERROR_MOUNT_ZFFFS: &str = "Error occurred while trying to mount the file(s): ";
pub(crate) const ERROR_ZFFFS_READ_SEEK: &str = "Could not read data at given offset.";
pub(crate) const ERROR_ZFFFS_READ_READ: &str = "An I/O error has occurred: ";
pub(crate) const ERROR_MISSING_ENCRYPTION_KEY: &str = "Zff file(s) are encrypted: You should enter the password by using the -p argument.";
pub(crate) const ERROR_UNREADABLE_INPUT_DIR: &str = "Could not read the directory of the given zff file: ";
pub(crate) const ERROR_UNDETERMINABLE_INPUT_DIR: &str = "could not determine input path!";

pub(crate) const EXIT_STATUS_ERROR: i32 = 1;
pub(crate) const EXIT_STATUS_SUCCESS: i32 = 0;

// fuser constants
pub(crate) const TTL: Duration = Duration::from_secs(1); // 1 second
pub(crate) const DEFAULT_BLOCKSIZE: u32 = 512;
pub(crate) const FILESYSTEM_NAME: &str = "zff-fs";

pub(crate) const DEFAULT_DIR_INODE: u64 = 1;

// metadata file
pub(crate) const DEFAULT_METADATA_NAME: &'static str = "metadata.toml";
pub(crate) const DEFAULT_METADATA_INODE: u64 = 2;
pub(crate) const DEFAULT_METADATA_FILE_PERMISSION: u16 = 0o644;
pub(crate) const DEFAULT_METADATA_HARDLINKS: u32 = 1;

// zff image file
pub(crate) const DEFAULT_ZFF_IMAGE_NAME: &'static str = "zff_image.dd";
pub(crate) const DEFAULT_ZFF_IMAGE_INODE: u64 = 3;
pub(crate) const DEFAULT_ZFF_IMAGE_FILE_PERMISSION: u16 = 0o644;
pub(crate) const DEFAULT_ZFF_IMAGE_HARDLINKS: u32 = 1;


pub(crate) const DEFAULT_DIR_ATTR: FileAttr = FileAttr {
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
pub(crate) const DEFAULT_ENTRY_GENERATION: u64 = 0;

// special paths
pub(crate) const PWD: &'static str = ".";