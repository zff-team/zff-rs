# Zff

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![website][website-image]][website-link]

Zff (Z forensic file format) is a completely new designed file format to store and handle the contents and structure of a partial or entire disk image, physical memory or logical file/folder structures.
The focus of zff is on speed, security and modularity in concert with forensic requirements. The modular design promises high maintainability and scalability.
Zff is an alternative to the ewf and aff file formats and is not compatible with them.

You can learn more about the file format and its specifications at [https://zff.dev](https://zff.dev).

## Features included in Zff(v2) (most of them are optional)

- ⚡ modern, blazingly fast methods to compress the dumped data (like Zstd or Lz4) ⚡
- 🔒 the data can optionally be stored encrypted. Strong AEAD and PBE algorithms are used.  🔒
- ☄ The format is built to be streamable (e.g. you could stream a zff dump/container via HTTP). ☄
- 🪂 Zff can handle both: logical dumps (like filesystem extractions) and physical dumps (like dd dumps). 🪂
- 🤹 The format is built to be splitable in multiple files. 🤹
- 🍱 You can store multiple dumps within one zff-container and extend an existing zff container with additional dumps. 🍱
- 🛡 To prevent manipulation attacks, the data can be stored signed. 🛡
- 🔗 Fast and modern hash algorithms are used to ensure the integrity of stored data. 🔗

## Zff tools and libraries

There are several tools (and this library) to work with zff containers (or acquire them). All tools and libraries are written in pure Rust.

| Name | Type | Description | Crates.io | MRSV
|------|:----:|:------------|:---------:|:----:|
| [zff](https://github.com/ph0llux/zff)  | library | Library to handle the zff format | [![crates.io][zff-crates-io-image]][zff-crates-io-link] | 1.58.1 |
| [zffacquire](https://github.com/ph0llux/zffacquire) | binary | Tool to acquire disk images in zff format | [![crates.io][zffacquire-crates-io-image]][zffacquire-crates-io-link] | 1.58.1 |
| [zffanalyze](https://github.com/ph0llux/zffanalyze) | binary | Tool to get information about a zff container | [![crates.io][zffanalyze-crates-io-image]][zffanalyze-crates-io-link] | 1.58.1 |
| [zffmount](https://github.com/ph0llux/zffmount) | binary | Tool to mount a zff container with FUSE (similar to xmount) | [![crates.io][zffmount-crates-io-image]][zffmount-crates-io-link] | 1.58.1 |

## Benchmarks

The following benchmarks were all run on a notebook, which has the following specifications:
- Dell XPS 13 9310 2-in-1
- 11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz
- 32GB LPDDR4x 4267 Mhz
- KBG40ZPZ1T02 NVMe KIOXIA 1024GB\
The installed operating system was Gentoo Linux.\
Input and output storage device was the internal NVMe.

The following benchmark was created for a \~20GB prebuilt image, which was generated using [this script](https://gist.github.com/ph0llux/6969329b060d393e199442dc0787dc9a).

![Acquisition time](/benchmarks/acquisition_time.png)
\
¹Using Guymager 0.8.12, with the default guymager.cfg, MD5 hash calculation, without "HashVerifyDest".\
²Using Guymager 0.8.12, with enabled Aff support and Aff compression level 1 in guymager.cfg, with MD5 hash calculation, without "HashVerifyDest".\
³using ```zffacquire physical -i raw/example01.dd -o zff_lz4 -z lz4```\
⁴using ```zffacquire physical -i raw/example01.dd -o zff -S per_chunk_signatures```\
⁵using ```zffacquire physical -i raw/example01.dd -o zff -p 123```\
⁶using ```zffacquire physical -i raw/example01.dd -o zff```\
⁷using ```ewfacquire example01.dd -t example01_ewf -f encase7-v2 -b 64 -c fast -S 7.9EiB -u```\
⁸using ```ewfacquire example01.dd -t example01_ewf -b 64 -c fast -S 7.9EiB -u```, using ewfacquire 20171104.\
⁹using ```linpmem-3.3-rc1 -i example01.dd -o output.aff4```\
¹⁰using ```linpmem-3.3-rc1 -i example01.dd -o output.aff4 --threads 8```\
¹¹using ```linpmem-3.3-rc1 -i example01.dd -o output.aff4 -c snappy```\
¹²using ```linpmem-3.3-rc1 -i example01.dd -o output.aff4 -c snappy --threads 8```\
¹³using ```linpmem-3.3-rc1 -i example01.dd -o output.aff4 -c lz4```\

As you can see, zffacquire is in most cases much faster than the other tools - even if you store the data encrypted. Using zffacquire with the default values gives no performance disadvantage. The situation is different, of course, with an additional signature operation (but the same would also apply to Guymager with "HashVerifyDest" and/or "HashVerifySrc" enabled).\
\
zffacquire and linpmem produce very good benchmarks using lz4 (which just goes to show how much switching compression algorithms can do!).

Two of the acquired images (The Guymager-e01-image at number 1, acquired in the benchmark process above and the zff-z01-image acquired with the default options of zffacquire, see above at number 6), the acquired Ex01-image (number 7) and the acquired Aff-image (by Guymager, see number 2), were used as the basis for the read speed benchmark.
For the benchmark, xmount and zffmount was used to FUSE mount the appropriate images. Next, dd was used to benchmark the read speed.

Unfortunately, I have not found an official reference tool that could have been used to FUSE mount aff4 images (neither on www.aff4.org nor on docs.aff4.org).
If someone can tell me one, I will update the benchmarks appropriately.

![Read speed](/benchmarks/read_speed_dd.png)
\
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

See the [website](https://zff.dev) for further information.

## License

Zff is open source and Apache 2.0 and MIT licensed. This should ensure compliance to use with both open source and commercial software.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[crate-image]: https://buildstats.info/crate/zff
[crate-link]: https://crates.io/crates/zff
[docs-image]: https://docs.rs/zff/badge.svg
[docs-link]: https://docs.rs/zff/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.58.1+-blue.svg
[website-image]: https://img.shields.io/website-up-down-green-red/http/zff.dev.svg
[website-link]: https://zff.dev

[zff-crates-io-image]: https://img.shields.io/crates/v/zff.svg
[zff-crates-io-link]: https://crates.io/crates/zff

[zffacquire-crates-io-image]: https://img.shields.io/crates/v/zffacquire.svg
[zffacquire-crates-io-link]: https://crates.io/crates/zffacquire

[zffanalyze-crates-io-image]: https://img.shields.io/crates/v/zffanalyze.svg
[zffanalyze-crates-io-link]: https://crates.io/crates/zffanalyze

[zffmount-crates-io-image]: https://img.shields.io/crates/v/zffmount.svg
[zffmount-crates-io-link]: https://crates.io/crates/zffmount
