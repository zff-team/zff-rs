# Zff – A Modern Forensic Container Format

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
![Rust Version][rustc-image]
[![codeberg][codeberg-image]][codeberg-link]

zff is a modern forensic container format designed for **high-performance acquisition, extensibility, scalability, and implementation clarity**.

Its modular design enables **maintainability and scalability** while supporting a wide range of forensic workflows.

It supports both **physical and logical evidence**, streaming workflows, optional encryption and signing, deduplication, and multiple objects per container.

zff is not intended as a drop-in replacement for all existing forensic exchange formats (such as EWF or AFF4).  
Instead, it provides a **clean, well-defined, and performant foundation** for building forensic tooling.

---

## Design Goals

- High-throughput acquisition and processing
- Support for both physical and logical evidence
- Streamable format design
- Clear and maintainable implementation
- Modern compression and cryptographic primitives
- Extensibility without excessive complexity

## Non-Goals

- Immediate full interoperability with all existing forensic tools
- Replicating legacy format behavior or constraints

See at the [wiki](https://github.com/ph0llux/zff/wiki) to learn more about the specification.

## Features (Zff v3)

- Physical and logical acquisition support
- Chunk-based storage model
- Streamable container format
- Optional compression (e.g. zstd, lz4)
- Optional encryption and signing
- Deduplication support
- Multiple objects per container
- Virtual objects (e.g. RAID reconstruction)
- Cross-platform support

## Why zff?

Existing forensic formats each have strengths:

- **EWF (E01/L01)**: widely used and broadly supported
- **AFF4**: flexible and conceptually powerful

However, they also involve trade-offs in areas such as:

- implementation complexity
- extensibility
- consistency across tooling
- adoption of modern compression and cryptographic primitives

zff explores a different design approach:

- a simpler and more consistent implementation model
- modern performance characteristics
- explicit support for both physical and logical evidence
- full control over format evolution and tooling

The goal is not to replace existing formats universally,  
but to provide a solid foundation for new forensic workflows.

## Zff tools and libraries

There are several tools (and this library) to work with zff containers (or acquire them). All tools and libraries are written in pure Rust.

| Name | Type | Description | Crates.io |
|------|:----:|:------------|:---------:|
| [zff](https://github.com/ph0llux/zff)  | library | Library to handle the zff format | [![crates.io][zff-crates-io-image]][zff-crates-io-link] | 
| [zffacquire](https://github.com/ph0llux/zffacquire) | binary | Tool to acquire disk images in zff format | [![crates.io][zffacquire-crates-io-image]][zffacquire-crates-io-link] |
| [zffanalyze](https://github.com/ph0llux/zffanalyze) | binary | Tool to get information about a zff container | [![crates.io][zffanalyze-crates-io-image]][zffanalyze-crates-io-link] |
| [zffmount](https://github.com/ph0llux/zffmount) | binary | Tool to mount a zff container with FUSE (similar to xmount) | [![crates.io][zffmount-crates-io-image]][zffmount-crates-io-link] | 

## Performance Notes

zff is designed for high performance through:

- chunk-based processing
- modern compression algorithms (e.g. zstd, lz4)
- efficient streaming design
- implementation in Rust

---

### Project Benchmarks

The following benchmarks evaluate the performance of **zff tooling** compared to selected acquisition tools.

> ⚠️ These results reflect **tool-level performance under specific conditions**, not a universal comparison of the underlying formats.

#### Test Setup

The following benchmarks were all run on a notebook, which has the following specifications:
- Lenovo Thinkbook 14S Yoga ITL  
- Intel(R) 11th Gen i5-1135G7 @ AVG: 2.40GHz (MAX: 4.2 GHz)  
- 16GB DDR4-3200 RAM  
- internal Samsung 980 Pro NVMe 1TB 
The installed operating system was Gentoo Linux.  
Input and output storage device was the internal NVMe.  

The following benchmark was created for a \~20GB prebuilt image, which was generated using [the benchmark script](/benchmarks/gen_benchmark_image.sh).

#### Results

> [WARNING!] Comparisons reflect specific tool implementations and configurations, not inherent properties of the formats themselves.

![Acquisition time](/benchmarks/acquisition_time.png)  

¹using ```ewfacquire example01.dd -t example01_ewf -b 64 -c fast -S 7.9EiB -u```, using ewfacquire 20171104.  
²using ```ewfacquire example01.dd -t example01_ewf -f encase7-v2 -b 64 -c fast -S 7.9EiB -u```  
³using ```zffacquire physical -i raw/example01.dd -o zff``` 
⁴using ```zffacquire physical -i raw/example01.dd -o zff -p -L debug```  
⁵using ```zffacquire physical -i raw/example01.dd -o zff -S```  
⁶using ```zffacquire physical -i raw/example01.dd -o zff_lz4 -z lz4```   
⁷Using Guymager 0.8.12, with the default guymager.cfg, MD5 hash calculation, without "HashVerifyDest".  
⁸Using Guymager 0.8.12, with enabled Aff support and Aff compression level 1 in guymager.cfg, with MD5 hash calculation, without "HashVerifyDest".  
⁹using ```linpmem-3.3-rc1 -i example01.dd -o output.aff4```  
¹⁰using ```linpmem-3.3-rc1 -i example01.dd -o output.aff4 --threads 8```  
¹¹using ```linpmem-3.3-rc1 -i example01.dd -o output.aff4 -c snappy```  
¹²using ```linpmem-3.3-rc1 -i example01.dd -o output.aff4 -c snappy --threads 8```  
¹³using ```linpmem-3.3-rc1 -i example01.dd -o output.aff4 -c lz4```  

![Read speed](/benchmarks/read_speed_dd.png)
\
¹The following commands were used:
```bash
zffmount -i zff.z01 -m /tmp/zffmount -c in-memory
dd if=/tmp/zffmount/zff_image.dd of=/dev/null bs=1M
```
²The following commands were used:
```bash
zffmount-v2 -i zff.z01 -m /tmp/zffmount
dd if=/tmp/zffmount/zff_image.dd of=/dev/null bs=1M
```
³The following commands were used:
```bash
affuse aff_image.aff /tmp/affmount
dd if=/tmp/affmount/aff_example01.aff.raw of=/dev/null bs=1M
```
⁴The following commands were used:
```bash
xmount --in aff aff_image.aff /tmp/affmount
dd if=/tmp/affmount/aff_image.dd of=/dev/null bs=1M
```
⁵The following commands were used:
```bash
xmount --in ewf ewfacquired.Ex01 /tmp/ewfmount
dd if=/tmp/ewfmount/ewfacquired.dd of=/dev/null bs=1M
```
⁶The following commands were used:
```bash
xmount --in ewf guymager.e01 /tmp/ewfmount
dd if=/tmp/ewfmount/guymager.dd of=/dev/null b=1M
```

### Interpretation

The results indicate that zff-based tooling can achieve competitive throughput in this specific setup.

However, performance depends heavily on:

- dataset characteristics
- compression configuration
- hardware (CPU vs I/O bound)
- implementation details of the compared tools

In particular, comparisons involving AFF4 should be interpreted carefully, as publicly available implementations differ significantly in feature coverage and performance behavior.

---

### Limitations

- Benchmarks were conducted on a single system and dataset
- Different tools expose different defaults and feature sets
- Not all formats have equally mature or comparable tooling
- Results should be considered **indicative, not definitive**

## Project Scope

zff is both:

- a **file format specification**
- a **reference implementation and tooling ecosystem**

The current implementation aims to:

- provide a complete and consistent reference
- validate format design decisions in practice
- enable real-world forensic workflows

Future development will focus on:

- improving tooling and usability
- expanding format features where necessary
- maintaining backward compatibility where possible



## Zff layout

See at the [wiki](https://github.com/ph0llux/zff/wiki) for further information.

## License

Zff is open source and Apache 2.0 and MIT licensed. This should ensure compliance to use with both open source and commercial software.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[codeberg-image]: https://img.shields.io/badge/Codeberg_Mirror-codeberg.org/zff--team/zff--rs-blue
[codeberg-link]: https://codeberg.org/zff-team/zff-rs
[crate-image]: https://img.shields.io/crates/v/zff
[crate-link]: https://crates.io/crates/zff
[docs-image]: https://docs.rs/zff/badge.svg
[docs-link]: https://docs.rs/zff/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[rustc-image]: https://img.shields.io/badge/rustc-1.67.1+-blue.svg
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
