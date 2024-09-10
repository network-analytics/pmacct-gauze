# pmacct-gauze

Rust library using FFI to bring [NetGauze](https://github.com/netgauze/netgauze)
into [pmacct](https://github.com/pmacct/pmacct).

This is still very experimental. The fork of pmacct with the pmacct-gauze integration can be found
at https://github.com/mxyns/pmacct/tree/netgauze-exp.

## How to use

### Prerequisites

- working C environment and Rust on the `nightly` channel
- [cargo-c](https://crates.io/crates/cargo-c)
    - install my fork `cargo install --git https://github.com/mxyns/cargo-c cargo-c` until
      this [PR](https://github.com/mozilla/cbindgen/pull/785) has been merged
- pmacct headers installed (see [install script](tools/install_pmacct_headers.sh))
    - or use the `PMACCT_INCLUDE_DIR` env variable to set the location of the headers.

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

## Conventions

### Memory Allocation

Memory allocated by Rust and given to C must be returned to and freed by Rust.
Allocating memory from Rust using a C function (`lcommunity_new`) is allowed as long as the memory is freed by
the correct C function (`lcommunity_free`) whether it's called from C or Rust.
No assumptions on the underlying allocator.

### Pointers

API Functions use raw pointers instead of references. All pointers are assumed non-null by contract.
While `cbindgen` is capable of automatically converting (mutable) reference
to raw pointers in the function prototypes, using raw pointers is cleaner.
When bad pointers are passed to Rust, the `.as_ref().unwrap()` will crash the program
and give informative errors like
```[...] panicked at 'called `Option::unwrap()` on a `None` value', src/filename.rs:linenumber:columnnumber```
instead of the classic `Segmentation Fault (core dumped)`.

The downside of this choice is the boilerplate code to check and cast each pointer.

TODO
Need to find a way to indicate ownership rules in function parameters other than the documentation 
