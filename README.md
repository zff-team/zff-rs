# Zff

> At the moment Zff version 2 is under development. The format has been overhauled for this purpose to add many new features and improvements. The associated tool suite (zffacquire, etc.) are currently also adapted to the new format, or are then accordingly downward compatible. The following new features will be added with version 2:
> - The format is built to be streamable (e.g. you could stream a zff dump/container directly via HTTP).
> - Zff can contain dumps within a container (e.g. if multiple disks belong to one device, so they stay together).
> - An existing Zff container can be easily extended with additional dumps.
> - You can add logical dumps/backups (complete folder structures are kept). Metadata such as the MdItems of MacOS can also be taken into account. Handling of files, folders, symlinks and hardlinks is possible.
> - Individual dumps/container can be encrypted with different encryption keys or passwords.
> - There is now a finer choice of signing (e.g. you can sign only the hash values, which allows a much faster dump, but also brings restrictions in the manipulation analysis).


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
- internal WDC PC SN530 512GB NVMe\
The installed operating system was Gentoo Linux.\
Input and output storage device was the internal NVMe.

The following benchmark was created for a \~20GB prebuilt image, which was generated using the script under benchmarks/example01.sh.
![Acquisition time](https://github.com/ph0llux/zff/blob/master/benchmark/acquisition_time.png?raw=true)
\
¹Using Guymager 0.8.12, with the default guymager.cfg, MD5 hash calculation, without "HashVerifyDest".\
²Using Guymager 0.8.12, with enabled Aff support and Aff compression level 1 in guymager.cfg, with MD5 hash calculation, without "HashVerifyDest".\
³using ```zffacquire -i raw/example01.dd -o zff_lz4 -z lz4```\
⁴using ```zffacquire -i raw/example01.dd -o zff -S```\
⁵using ```zffacquire -i raw/example01.dd -o zff -p 123```\
⁶using ```zffacquire -i raw/example01.dd -o zff```\
⁷using ```ewfacquire example01.dd -t example01_ewf -f encase7-v2 -b 64 -c fast -S 7.9EiB -u```\
⁸using ```ewfacquire example01.dd -t example01_ewf -b 64 -c fast -S 7.9EiB -u```, using ewfacquire 20171104.\

As you can see, there are hardly any differences worth mentioning between the dump using Guymager and zffacquire. Using zffacquire with the default values gives no performance disadvantage. The situation is different, of course, with an additional signature operation (but the same would also apply to Guymager with "HashVerifyDest" and/or "HashVerifySrc" enabled).\
\
The two fastest images (The Guymager-e01-image at number 1, acquired in the benchmark process above and the zff-z01-image acquired with the default options of zffacquire, see above at number 6), the acquired Ex01-image (number 7) and the acquired Aff-image (by Guymager, see number 2), were used as the basis for the read speed benchmark.
For the benchmark, xmount and zffmount was used to FUSE mount the appropriate images. Next, dd was used to benchmark the read speed.
The dd commands were applied 10 times and then an average value was calculated over the determined values.
![Read speed](https://github.com/ph0llux/zff/blob/master/benchmark/read_speed_dd.png?raw=true)\
¹The following commands were used:
```bash
zffmount -i zff.z01 -m /tmp/zffmount
dd if=/tmp/zffmount/zff_image.dd of=/dev/null bs=1M
```
²The following commands were used:
```bash
affuse aff_image.aff /tmp/affmount
dd if=/tmp/affmount/aff_example01.aff.raw of=/dev/null bs=1M
```
³The following commands were used:
```bash
xmount --in aff aff_image.aff /tmp/affmount
dd if=/tmp/affmount/aff_image.dd of=/dev/null bs=1M
```
⁴The following commands were used:
```bash
xmount --in ewf ewfacquired.Ex01 /tmp/ewfmount
dd if=/tmp/ewfmount/ewfacquired.dd of=/dev/null bs=1M
```
⁵The following commands were used:
```bash
xmount --in ewf guymager.e01 /tmp/ewfmount
dd if=/tmp/ewfmount/guymager.dd of=/dev/null b=1M
```
## Zff layout

See the [wiki pages](https://github.com/ph0llux/zff/wiki/Zff-layout) for further information.

## Zff tools and libraries

This repository contains several tools to work with zff images (or acquire them). All tools and libraries are written in pure Rust.

| Name | Type | Description | Crates.io | MRSV
|------|:----:|:------------|:---------:|:----:|
| [zff](https://github.com/ph0llux/zff/tree/master/zff)  | library | Library to handle the zff format | [![crates.io][zff-crates-io-image]][zff-crates-io-link] | 1.58.1 |
| [zffacquire](https://github.com/ph0llux/zffacquire) | binary | Tool to acquire disk images in zff format | [![crates.io][zffacquire-crates-io-image]][zffacquire-crates-io-link] | 1.58.1 |
| [zffanalyze](https://github.com/ph0llux/zffanalyze) | binary | Tool to get information about a zff container | [![crates.io][zffanalyze-crates-io-image]][zffanalyze-crates-io-link] | 1.58.1 |
| [zffmount](https://github.com/ph0llux/zffmount) | binary | Tool to mount a zff container with FUSE (similar to xmount) | [![crates.io][zffmount-crates-io-image]][zffmount-crates-io-link] | 1.56.1 |

[//]: # (badges)

[deps-image]: https://deps.rs/repo/github/ph0llux/zff/status.svg
[deps-link]: https://deps.rs/repo/github/ph0llux/zff

[zff-crates-io-image]: https://img.shields.io/crates/v/zff.svg
[zff-crates-io-link]: https://crates.io/crates/zff

[zffacquire-crates-io-image]: https://img.shields.io/crates/v/zffacquire.svg
[zffacquire-crates-io-link]: https://crates.io/crates/zffacquire

[zffanalyze-crates-io-image]: https://img.shields.io/crates/v/zffanalyze.svg
[zffanalyze-crates-io-link]: https://crates.io/crates/zffanalyze

[zffmount-crates-io-image]: https://img.shields.io/crates/v/zffmount.svg
[zffmount-crates-io-link]: https://crates.io/crates/zffmount
