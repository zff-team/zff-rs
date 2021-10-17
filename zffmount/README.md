# zffmount

```zffmount``` is a command line utility to mount a zff image using FUSE.

# Installation

First, you need to [install rust and cargo](https://rustup.rs/) to build or install ```zffmount```.
Then you can easily build this tool yourself by using cargo:
```bash
[/home/ph0llux/projects/zffmount] $ cargo build --release
```
Or you can install the tool directly from crates.io:
```bash
$ cargo install zffmount
```

# Usage

Use ```zffmount -i <YOUR_ZFF_IMAGE.z01> -m /mnt/your_mountpoint``` to mount the image to /mnt/your_mountpoint.
The acquired data that underlies the image is represented as a dd file. This is an on-the-fly conversion.