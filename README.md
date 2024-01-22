# pmacct-gauze

Rust library using FFI to bring [NetGauze](https://github.com/netgauze/netgauze) into [pmacct](https://github.com/pmacct/pmacct). 

This is still very experimental. The fork of pmacct with the pmacct-gauze integration can be found at https://github.com/mxyns/pmacct/tree/netgauze-exp. 

## How to use

### Prerequisites
- working Rust and C environments
- [cargo-c](https://crates.io/crates/cargo-c)
- pmacct headers installed (see [install script](tools/install_pmacct_headers.sh))
  - or use the `PMACCT_INCLUDE_DIR` env variable to set the location of the headers but be careful of cyclic dependencies. 
- the following file tree structure
  - `.` some folder
    - `netgauze` clone root folder (use my [fork](https://github.com/netgauze/netgauze)) 
    - `pmacct-gauze` root folder for this project

If you want to place netgauze / pmacct-gauze elsewhere, change the netgauze dependencies location in [Cargo.toml](crates/pmacct-gauze-lib/Cargo.toml).

### Build and install pmacct-gauze
`cargo cinstall -vv --package pmacct-gauze-lib`
use `-vv` for very verbose output.

Now the library and the headers are installed on your machine. It's time to build pmacct with pmacct-gauze.

### Build and install pmacct with pmacct-gauze

Use this version of pmacct: https://github.com/mxyns/pmacct/tree/netgauze-exp

Follow pmacct build instructions, and configure with 
```shell
./configure CFLAGS=-I/usr/local/include/pmacct_gauze_lib 'LIBS=-L/usr/local/lib -lpmacct_gauze_lib' --enable-jansson
```
until I integrate the lib correctly in pmacct's build system. 

`/usr/local/lib` is the default installation dir for `cargo-c` on Linux systems. 
You can change it to where your pmacct-gauze is actually installed.

### Run pmacct

Just build (+ install) and run pmacct. I use the following, use whatever suits you best in your environment.
```shell
sudo make install -j8 && valgrind --leak-check=full pmbmpd -I ~/bmp-community-ecommunity-frr-clean.pcapng -f ./config -o /tmp/bmp.log
```