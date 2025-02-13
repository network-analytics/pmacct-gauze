# pmacct-gauze

Rust library using FFI to bring [NetGauze](https://github.com/netgauze/netgauze)
into [pmacct](https://github.com/pmacct/pmacct).

This is still very experimental. The fork of pmacct with the pmacct-gauze integration can be found
at https://github.com/mxyns/pmacct/tree/netgauze-exp.

## How to use

### Prerequisites

- working C and Rust environments with Rust toolchain on the `nightly` channel

### Build and install pmacct-gauze with pmacct

#### Build locally

Read and then run this.

```bash
git clone --recurse-submodules -b netgauze-exp https://github.com/mxyns/pmacct/ 
cd pmacct

# Install libcdada manually. libcdada headers are needed for the pmacct headers to be valid
cd src/external_libs/libcdada && ./autogen.sh && ./configure && make -j8 install
cd ../../.. # Back to pmacct

# Go and install all pmacct dependencies listed in the pmacct documentation.
# I will not list them here since they may change

# Configure pmacct once without pmacct-gauze to generate pmacct-version.h
# Also needed for the headers to be valid
./autogen.sh && ./configure
cd .. # Back to root

# Install my fork of [cargo-c](https://crates.io/crates/cargo-c)
cargo install --git https://github.com/mxyns/cargo-c cargo-c

# Clone and install pmacct-gauze
git clone https://github.com/mxyns/pmacct-gauze
cd pmacct-gauze

# /!\ IMPORTANT /!\
# Here pmacct-gauze needs to have access the pmacct headers.
# One way is to install them using the pmacct headers install script 
# ./tools/install_pmacct_headers.sh <source> [target]
#   - source here would be "../pmacct"
#   - target, in general (and by default) is "/usr/local/include/pmacct"
# Another way is to use the `PMACCT_INCLUDE_DIR` env variable to set the location of the headers
# before building pmacct-gauze. Useful when developing.
# This can be done either in pmacct-gauze/.cargo/config.toml or via command line
export PMACCT_INCLUDE_DIR=$(realpath ..); cargo cinstall -vv --package pmacct-gauze-lib
ldconfig # Force library cache update
cd .. # Back to root

# Manually cleanup the pmacct repository 
cd pmacct && rm -rf src/external_libs/libcdada

# Configure and install pmacct, but with pmacct-gauze enabled now
# cargo cinstall has installed the headers and library files in some directory (a default or custom one) of your OS
# You need to ensure that pkg-config is configured to find those files on your machine:
# - Ubuntu everything works by default.
# - Debian: export PKG_CONFIG_PATH=/usr/local/lib64/pkgconfig
./configure --enable-pmacct-gauze # Add whatever other flags you need here
make -j8 install
```

#### Docker

Docker images can be built
from [Dockerfile](https://github.com/mxyns/pmacct/blob/netgauze-exp/docker/pmacct-gauze-base/Dockerfile)
You will need to have pmacct-gauze cloned in pmacct/docker:
```
git clone --recurse-submodules -b netgauze-exp https://github.com/mxyns/pmacct
git clone https://github.com/mxyns/pmacct-gauze pmacct/docker/pmacct-gauze
cd pmacct; docker build -f docker/pmacct-gauze-base/Dockerfile .
```

## Conventions

### Avoiding circular dependencies

Circular dependencies in the headers between pmacct-gauze and pmacct can happen.
In order to avoid them, all items that need to be ignored by pmacct must be wrapped in
an `#ifndef PMACCT_GAUZE_BUILD` guard.
Items that need to be ignored are, non-exhaustively:

- pmacct-gauze header inclusions
- method declarations and definitions that use pmacct-gauze types

Example from pmacct/src/bmp/bmp_msg.h:

```c
struct SomeStructUnrelatedToPmacctGauze {
    // fields...
};

#ifndef PMACCT_GAUZE_BUILD
#include "pmacct_gauze_lib/pmacct_gauze_lib.h"

extern u_int32_t bmp_process_packet(char *, u_int32_t, struct bmp_peer *, int *);
extern void bmp_process_msg_init(struct bmp_peer *, ParsedBmp *);
extern void bmp_process_msg_term(struct bmp_peer *, const ParsedBmp *);
extern void bmp_process_msg_peer_up(struct bmp_peer *, const ParsedBmp *);
extern void bmp_process_msg_peer_down(struct bmp_peer *, const ParsedBmp *);
extern void bmp_process_msg_stats(struct bmp_peer *, const ParsedBmp *);
extern void bmp_process_msg_route_monitor(struct bmp_peer *, const ParsedBmp *);
extern void bmp_process_msg_route_mirror(struct bmp_peer *);

extern Opaque_BmpParsingContext *bmp_parsing_context_get(struct bmp_peer *bmp_peer);
extern Opaque_ContextCache *bmp_context_cache_get();
extern void bmp_parsing_context_clear(struct bmp_peer *bmp_peer);
#endif

#endif //BMP_MSG_H
```

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
