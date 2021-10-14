# Zff

Zff (Z forensic file format) is a completley new designed file format to store and handle the contents and structure of a partial or entire disk image or physical memory.
The focus of zff is on speed, security and modularity in concert with forensic requirements.The modular design promises high maintainability and scalability.
Zff is an alternative to the ewf and aff file formats and is not compatible with them.

## Features included in zff (most of them are optional)
- The disk image can be stored in several split segments.
- The data can be stored in compressed format (modern [compression algorithms](https://github.com/ph0llux/zff/wiki/Zff-layout#compression-algorithm-flag) like __Zstd__)
- The stored data can be optionally encrypted with a password. Used here are best practices reccomended by PKCS#5 (see [KDF schemes](https://github.com/ph0llux/zff/wiki/Zff-layout#kdf-flag) and [encryption schemes](https://github.com/ph0llux/zff/wiki/Zff-layout#encryption-scheme-flag) for available implementations). The encryption of the data is performed using AEAD (Authenticated Encryption with Associated Data) algorithms. Currently implemented algorithms are listed in the [encryption algorithms](https://github.com/ph0llux/zff/wiki/Zff-layout#encryption-algorithms) section.
- The integrity of the stored data can optionally be ensured by using cryptographic hash values. The available hash algorithms are listed in the [hash types](https://github.com/ph0llux/zff/wiki/Zff-layout#hash-types-flag) section.
- The authenticity of the data can be additionally ensured by digital signatures. The asymmetric signature algorithm __Ed25519__ is used for this purpose.
- The stored data is organized in small chunks. 
Above mentioned compression, encryption and signature methods are applied to each chunk separately. This makes it possible to access a corresponding part of the data in real time without the need to decompress or decrypt the complete image first.
Authenticity verification can also be applied to individual chunks and does not have to be applied to the entire image.

## benchmarks

coming soon.

## Zff layout

See the [wiki pages](https://github.com/ph0llux/zff/wiki/Zff-layout) for further information.

## Zff tools and libraries

This repository contains several tools to work with zff images (or acquire them). All tools and libraries are written in pure Rust.

| Name | Type | Description | Crates.io | MRSV |
|------|:----:|:------------|:---------:|:----:|
| zff  | library | Library to handle the zff format | coming soon | 1.55 |
| zffacquire | binary | Tool to acquire disk images in zff format | coming soon | 1.55 |
| zffmetareader | binary | Tool to get meta information about a zff image | coming soon | 1.55 |
| zffmount | binary | Tool to mount a zff image with FUSE (similar to xmount) | coming soon | 1.55 |

# Planned features until zff reaches version 1.0
- testing / unit tests
- parallel implementation of hashing/crc/signing<->writing data
- tool to verify the ed25519 signature
- show a well formatted date/time (instead of a timestamp) at the serialized header information