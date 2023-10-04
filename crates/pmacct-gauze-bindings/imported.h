// Here we import all C headers needed by Rust


// std headers forgotten in pmacct
#include <stdlib.h>
#include <arpa/inet.h>

// WHY?
#include <sys/types.h>

// pmacct headers (no bindings generated)
#include <pcap.h>
#include <pmacct/src/pmacct.h>
#include <pmacct/src/addr.h>
#include <pmacct/src/plugin_hooks.h>
#include <pmacct/src/network.h>
#include <pmacct/src/bgp/bgp.h>

// pmacct headers (bindings generated)
#include <pmacct/src/bmp/bmp.h>
