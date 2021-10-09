// - STD
use std::process::exit;
use std::path::PathBuf;
use std::fs::{File,read_dir};
use std::ffi::OsStr;
use std::time::{UNIX_EPOCH};
use std::io::{Read, Seek, SeekFrom};

// - modules
mod lib;

// - internal
use zff::{
    Result,
    header::*,
    HeaderCoding,
    ZffReader,
    ZffError,
    ZffErrorKind,
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

struct ZffFS<R: 'static +  Read + Seek> {
    zff_reader: ZffReader<R>,
}

impl<R: Read + Seek> ZffFS<R> {
    fn new(mut data: Vec<R>) -> Result<ZffFS<R>> {
        let main_header = MainHeader::decode_directly(&mut data[0])?;
        if let Some(_) = main_header.encryption_header() {
            return Err(ZffError::new(ZffErrorKind::MissingEncryptionKey, ERROR_MISSING_ENCRYPTION_KEY));
        };
        let zff_reader = ZffReader::new(data, main_header)?;
        Ok(Self {
            zff_reader: zff_reader,
        })
    }

    fn new_encrypted<P: AsRef<[u8]>>(mut data: Vec<R>, password: P) -> Result<ZffFS<R>> {
        let main_header = match MainHeader::decode_directly(&mut data[0]) {
            Ok(header) => header,
            Err(e) => match e.get_kind() {
                ZffErrorKind::HeaderDecodeMismatchIdentifier => {
                    data[0].seek(SeekFrom::Start(0))?;
                    MainHeader::decode_encrypted_header_with_password(&mut data[0], &password)?
                },
                _ => return Err(e),
            },
        };
        let mut zff_reader = ZffReader::new(data, main_header)?;
        zff_reader.decrypt_encryption_key(password)?;
        Ok(Self {
            zff_reader: zff_reader,
        })
    }

    //TODO return Result<FileAttr>.
    fn metadata_fileattr(&self) -> FileAttr {
        let serialized_data = match toml::Value::try_from(&self.zff_reader.main_header()) {
            Ok(value) => value.to_string(),
            Err(_) => {
                println!("{}", ERROR_SERIALIZE_METADATA);
                exit(EXIT_STATUS_ERROR);
            }
        };
        let attr = FileAttr {
            ino: DEFAULT_METADATA_INODE,
            size: serialized_data.len() as u64,
            blocks: serialized_data.len() as u64 / DEFAULT_BLOCKSIZE as u64 + 1,
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

    fn zff_image_fileattr(&self) -> FileAttr {
        let size = self.zff_reader.main_header().length_of_data();
        let attr = FileAttr {
            ino: DEFAULT_ZFF_IMAGE_INODE,
            size: size,
            blocks: size / DEFAULT_BLOCKSIZE as u64 + 1,
            atime: UNIX_EPOCH, // 1970-01-01 00:00:00
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::RegularFile,
            perm: DEFAULT_ZFF_IMAGE_FILE_PERMISSION,
            nlink: DEFAULT_ZFF_IMAGE_HARDLINKS,
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
        let serialized_data = match toml::Value::try_from(&self.zff_reader.main_header()) {
            Ok(value) => value,
            Err(_) => {
                println!("{}", ERROR_SERIALIZE_METADATA);
                exit(EXIT_STATUS_ERROR);
            }
        };
        serialized_data.to_string()
    }
}

impl<R: Read + Seek> Filesystem for ZffFS<R> {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if parent == DEFAULT_DIR_INODE && name.to_str() == Some(DEFAULT_METADATA_NAME) {
            reply.entry(&TTL, &self.metadata_fileattr(), DEFAULT_ENTRY_GENERATION);
        } else if parent == DEFAULT_DIR_INODE && name.to_str() == Some(DEFAULT_ZFF_IMAGE_NAME) {
            reply.entry(&TTL, &self.zff_image_fileattr(), DEFAULT_ENTRY_GENERATION);
        } else {
            reply.error(ENOENT);
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        match ino {
            DEFAULT_DIR_INODE => reply.attr(&TTL, &DEFAULT_DIR_ATTR),
            DEFAULT_METADATA_INODE => reply.attr(&TTL, &self.metadata_fileattr()),
            DEFAULT_ZFF_IMAGE_INODE => reply.attr(&TTL, &self.zff_image_fileattr()),
            _ => reply.error(ENOENT),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        if ino == DEFAULT_METADATA_INODE {
            reply.data(&self.serialize_metadata().as_bytes()[offset as usize..]);
        } else if ino == DEFAULT_ZFF_IMAGE_INODE {
            let mut buffer = vec![0u8; size as usize];
            match self.zff_reader.seek(SeekFrom::Start(offset as u64)) {
                Ok(_) => (),
                Err(_) => {
                    println!("{}", ERROR_ZFFFS_READ_SEEK);
                    exit(EXIT_STATUS_ERROR);
                }
            };
            match self.zff_reader.read(&mut buffer) {
                Ok(_) => (),
                Err(e) => println!("{}{}", ERROR_ZFFFS_READ_READ, e.to_string()),
            };
            reply.data(&buffer);
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
            (DEFAULT_ZFF_IMAGE_INODE, FileType::RegularFile, DEFAULT_ZFF_IMAGE_NAME),
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
                    .arg(Arg::with_name(CLAP_ARG_NAME_PASSWORD)
                        .help(CLAP_ARG_HELP_PASSWORD)
                        .short(CLAP_ARG_SHORT_PASSWORD)
                        .long(CLAP_ARG_LONG_PASSWORD)
                        .takes_value(true))
                    .get_matches();
    matches
}

fn main() {
    let arguments = arguments();

    // Calling .unwrap() is safe here because the arguments are *required*.
    let input_filename = PathBuf::from(arguments.value_of(CLAP_ARG_NAME_INPUT_FILE).unwrap());
    let mut input_file_paths = Vec::new();

    let input_path = match PathBuf::from(&input_filename).parent() {
        Some(p) => match read_dir(p) {
            Ok(iter) => iter,
            Err(_) => {
                //TODO
                println!("errr");
                exit(EXIT_STATUS_ERROR);
            }
        },
        None => {
            //TODO
            println!("could not determine input path!");
            exit(EXIT_STATUS_ERROR);
        }
    };
    for filename in input_path {
        match filename {
            Ok(n) if n.path().is_file() => {
                if n.path().file_stem() == input_filename.file_stem() {
                    input_file_paths.push(n.path());
                }
            }
            _ => ()
        }
    }
    let mountpoint = PathBuf::from(arguments.value_of(CLAP_ARG_NAME_MOUNT_DIR).unwrap());

    input_file_paths.sort();
    let mut input_files = Vec::new();
    for path in input_file_paths {
        let segment_file = match File::open(&path) {
            Ok(file) => file,
            Err(_) => {
                println!("{}{}", ERROR_OPEN_INPUT_FILE, path.to_string_lossy());
                exit(EXIT_STATUS_ERROR);
            }
        };
        input_files.push(segment_file);
    }

    let zff_fs = if !arguments.is_present(CLAP_ARG_NAME_PASSWORD) {
        match ZffFS::new(input_files) {
            Ok(fs) => fs,
            Err(e) => {
                //TODO: check if file is an encrypted zff file and show a appropriate message.
                println!("{}{}", ERROR_CREATE_ZFFFS, e.to_string());
                exit(EXIT_STATUS_ERROR);
            },
        }
    } else {
        //unwrap is safe here, because we have checked value presence earlier.
        let password = arguments.value_of(CLAP_ARG_NAME_PASSWORD).unwrap();
        match ZffFS::new_encrypted(input_files, password.trim()) {
            Ok(fs) => fs,
            Err(e) => {
                //TODO: improve error message.
                println!("{}{}", ERROR_CREATE_ZFFFS, e.to_string());
                exit(EXIT_STATUS_ERROR);
            },
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

