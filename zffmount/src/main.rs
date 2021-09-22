// - STD
use std::process::exit;
use std::path::PathBuf;
use std::fs::File;
use std::ffi::OsStr;
use std::time::{UNIX_EPOCH};
use std::io::{Read};

// - modules
mod lib;

// - internal
use zff::{
    Result,
    header::*,
    HeaderDecoder,
};
use lib::constants::*;

// - external
use clap::{App, Arg, ArgMatches};
use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};
use libc::ENOENT;
use toml;
use nix::unistd::{Uid, Gid};

struct ZffFS {
    zff_header: MainHeader,
}

impl ZffFS {
    fn new<R: Read>(data: &mut R) -> Result<ZffFS> {
        let main_header = MainHeader::decode_directly(data)?;
        Ok(Self {
            zff_header: main_header,
        })
    }

    //TODO return Result<FileAttr>.
    fn metadata_fileattr(&self) -> FileAttr {
        let serialized_data = match toml::Value::try_from(&self.zff_header) {
            Ok(value) => value.to_string(),
            Err(_) => {
                println!("{}", ERROR_SERIALIZE_METADATA);
                exit(EXIT_STATUS_ERROR);
            }
        };
        let attr = FileAttr {
            ino: DEFAULT_METADATA_INODE,
            size: serialized_data.len() as u64,
            blocks: 10,
            atime: UNIX_EPOCH, // 1970-01-01 00:00:00
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::RegularFile,
            perm: DEFAULT_METADATA_FILE_PERMISSION,
            nlink: DEFAULT_METADATA_HARDLINKS,
            uid: Uid::effective().into(),
            gid: Gid::effective().into(),
            rdev: 0,
            flags: 0,
            blksize: DEFAULT_BLOCKSIZE,
        };
        attr
    }

    //TODO return Result<String>.
    fn serialize_metadata(&self) -> String {
        let serialized_data = match toml::Value::try_from(&self.zff_header) {
            Ok(value) => value,
            Err(_) => {
                println!("{}", ERROR_SERIALIZE_METADATA);
                exit(EXIT_STATUS_ERROR);
            }
        };
        serialized_data.to_string()
    }
}

impl Filesystem for ZffFS {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == DEFAULT_DIR_INODE && name.to_str() == Some(DEFAULT_METADATA_NAME) {
            reply.entry(&TTL, &self.metadata_fileattr(), DEFAULT_ENTRY_GENERATION);
        } else {
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match ino {
            DEFAULT_DIR_INODE => reply.attr(&TTL, &DEFAULT_DIR_ATTR),
            DEFAULT_METADATA_INODE => reply.attr(&TTL, &self.metadata_fileattr()),
            _ => reply.error(ENOENT),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        _size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        if ino == DEFAULT_METADATA_INODE {
            reply.data(&self.serialize_metadata().as_bytes()[offset as usize..]);
        } else {
            reply.error(ENOENT);
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if ino != DEFAULT_DIR_INODE {
            reply.error(ENOENT);
            return;
        }

        let entries = vec![
            (DEFAULT_DIR_INODE, FileType::Directory, "."),
            (DEFAULT_DIR_INODE, FileType::Directory, ".."),
            (DEFAULT_METADATA_INODE, FileType::RegularFile, DEFAULT_METADATA_NAME),
        ];

        for (i, entry) in entries.into_iter().enumerate().skip(offset as usize) {
            // i + 1 means the index of the next entry
            if reply.add(entry.0, (i + 1) as i64, entry.1, entry.2) {
                break;
            }
        }
        reply.ok();
    }
}

fn arguments() -> ArgMatches<'static> {
    let matches = App::new(PROGRAM_NAME)
                    .version(PROGRAM_VERSION)
                    .author(PROGRAM_AUTHOR)
                    .about(PROGRAM_DESCRIPTION)
                    .arg(Arg::with_name(CLAP_ARG_NAME_INPUT_FILE)
                        .help(CLAP_ARG_HELP_INPUT_FILE)
                        .short(CLAP_ARG_SHORT_INPUT_FILE)
                        .long(CLAP_ARG_LONG_INPUT_FILE)
                        .required(true)
                        .takes_value(true))
                    .arg(Arg::with_name(CLAP_ARG_NAME_MOUNT_DIR)
                        .help(CLAP_ARG_HELP_MOUNT_DIR)
                        .short(CLAP_ARG_SHORT_MOUNT_DIR)
                        .long(CLAP_ARG_LONG_MOUNT_DIR)
                        .required(true)
                        .takes_value(true))
                    .get_matches();
    matches
}

fn main() {
    let arguments = arguments();

    // Calling .unwrap() is safe here because the arguments are *required*.
    let input_path = PathBuf::from(arguments.value_of(CLAP_ARG_NAME_INPUT_FILE).unwrap());
    let mut input_file = match File::open(input_path) {
        Ok(file) => file,
        Err(_) => {
            println!("{}", ERROR_OPEN_INPUT_FILE);
            exit(EXIT_STATUS_ERROR);
        }
    };
    let mountpoint = PathBuf::from(arguments.value_of(CLAP_ARG_NAME_MOUNT_DIR).unwrap());

    let zff_fs = match ZffFS::new(&mut input_file) {
        Ok(fs) => fs,
        Err(e) => {
            println!("{}{}", ERROR_CREATE_ZFFFS, e.to_string());
            exit(EXIT_STATUS_ERROR);
        }
    };
    let mountoptions = vec![MountOption::RO, MountOption::FSName(FILESYSTEM_NAME.to_string())];
    match fuser::mount2(zff_fs, mountpoint, &mountoptions) {
        Ok(_) => (),
        Err(e) => {
            println!("{}{}", ERROR_MOUNT_ZFFFS, e.to_string());
            exit(EXIT_STATUS_ERROR);
        }
    };
    exit(EXIT_STATUS_SUCCESS);
}

