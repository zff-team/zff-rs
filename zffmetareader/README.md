# zffmetareader

```zffmetareader``` is a command line utility to read the metadata of a zff image.

# Installation

First, you need to [install rust and cargo](https://rustup.rs/) to build or install ```zffmetareader```.
Then you can easily build this tool yourself by using cargo:
```bash
[/home/ph0llux/projects/zffmetareader] $ cargo build --release
```
Or you can install the tool directly from crates.io:
```bash
$ cargo install zffmetareader
```

# Usage

Use ```zffmetareader -i <YOUR_ZFF_IMAGE.z01>``` to read the metadata of a zff file.