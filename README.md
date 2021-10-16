# Zff

[![dependency status][deps-image]][deps-link]

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

The following benchmarks were all run on my notebook, which has the following specifications:
- Lenovo Thinkbook 14S Yoga ITL
- Intel(R) 11th Gen i5-1135G7 @ AVG: 2.40GHz (MAX: 4.2 GHz)
- 16GB DDR4-3200 RAM
- internal WDC PC SN530 512GB NVMe
The installed operating system was Gentoo Linux.
Input and output storage device was the internal NVMe.

![Acquisition time](https://github.com/ph0llux/zff/blob/master/benchmark/acquisition_time.png?raw=true)

![Read speed](https://github.com/ph0llux/zff/blob/master/benchmark/read_speed_dd.png?raw=true)

## Zff layout

See the [wiki pages](https://github.com/ph0llux/zff/wiki/Zff-layout) for further information.

## Zff tools and libraries

This repository contains several tools to work with zff images (or acquire them). All tools and libraries are written in pure Rust.

| Name | Type | Description | Crates.io | MRSV |
|------|:----:|:------------|:---------:|:----:|
| [zff](https://github.com/ph0llux/zff/tree/master/zff)  | library | Library to handle the zff format | [![crates.io][zff-crates-io-image]][zff-crates-io-link] | 1.55 |
| [zffacquire](https://github.com/ph0llux/zff/tree/master/zffacquire) | binary | Tool to acquire disk images in zff format | [![crates.io][zffacquire-crates-io-image]][zffacquire-crates-io-link] | 1.55 |
| [zffmetareader](https://github.com/ph0llux/zff/tree/master/zffmetareader) | binary | Tool to get meta information about a zff image | [![crates.io][zffmetareader-crates-io-image]][zffmetareader-crates-io-link] | 1.55 |
| [zffmount](https://github.com/ph0llux/zff/tree/master/zffmount) | binary | Tool to mount a zff image with FUSE (similar to xmount) | [![crates.io][zffmount-crates-io-image]][zffmount-crates-io-link] | 1.55 |

[//]: # (badges)

[deps-image]: https://deps.rs/repo/github/ph0llux/zff/status.svg
[deps-link]: https://deps.rs/repo/github/ph0llux/zff

[zff-crates-io-image]: https://img.shields.io/crates/v/zff.svg
[zff-crates-io-link]: https://crates.io/crates/zff

[zffacquire-crates-io-image]: https://img.shields.io/crates/v/zffacquire.svg
[zffacquire-crates-io-link]: https://crates.io/crates/zffacquire

[zffmetareader-crates-io-image]: https://img.shields.io/crates/v/zffmetareader.svg
[zffmetareader-crates-io-link]: https://crates.io/crates/zffmetareader

[zffmount-crates-io-image]: https://img.shields.io/crates/v/zffmount.svg
[zffmount-crates-io-link]: https://crates.io/crates/zffmount