# pmacct-gauze

Rust library using FFI to bring [NetGauze](https://github.com/netgauze/netgauze) into [pmacct](https://github.com/pmacct/pmacct). 

This is still very experimental. The fork of pmacct with the pmacct-gauze integration can be found at https://github.com/mxyns/pmacct/tree/netgauze-exp. 

## How to use

### Prerequisites
- working Rust and C environments
- [cargo-c](https://crates.io/crates/cargo-c)
  - install my fork `cargo install --git https://github.com/mxyns/cargo-c cargo-c` until this [PR](https://github.com/mozilla/cbindgen/pull/785) has been merged
- pmacct headers installed (see [install script](tools/install_pmacct_headers.sh))
  - or use the `PMACCT_INCLUDE_DIR` env variable to set the location of the headers.
- the following file tree structure
  - `.` some folder
    - `netgauze` clone root folder (use my [fork](https://github.com/mxyns/netgauze) to ensure the netgauze version is compatible with pmacct-gauze last version) 
    - `pmacct-gauze` root folder for this project

If you want to place netgauze / pmacct-gauze elsewhere, change the netgauze dependencies location in [Cargo.toml](crates/pmacct-gauze-lib/Cargo.toml).

### Build and install pmacct-gauze
`cargo cinstall -vv --package pmacct-gauze-lib`
use `-vv` for very verbose output.

Now the library and the headers are installed on your machine. It's time to build pmacct with pmacct-gauze.

### Build and install pmacct with pmacct-gauze

Use this version of pmacct: https://github.com/mxyns/pmacct/tree/netgauze-exp

Follow pmacct build instructions, configure with `--enable-pmacct-gauze` and build pmacct. 
pmacct-gauze should be linked automatically using pkg-config.

### Run pmacct

Just run pmacct. I use the following when developing pmacct-gauze, use whatever suits you best in your environment.
```shell
sudo make install -j8 && valgrind --leak-check=full pmbmpd -I ~/bmp-community-ecommunity-frr-clean.pcapng -f ./config -o /tmp/bmp.log
```
