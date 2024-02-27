#![feature(try_trait_v2)]
#![feature(vec_into_raw_parts)]
#![feature(ptr_metadata)]
#![feature(ip_bits)]
#![feature(offset_of)]

// TODO add testing that validates return values using C functions
// TODO derive macro for automatic c function print for structs/enums implementation

/// The actual methods exposed to C
#[cfg(feature = "capi")]
pub mod capi;

/// Representation of a [Option] but FFI-compatible
pub mod coption;

/// Representation of a [Result] but FFI-compatible
pub mod cresult;

/// Representation of a slice in C. Allows converting from/to [Vec]
pub mod cslice;

/// Extension traits with helper functions for NetGauze types
pub mod extensions;

#[macro_use]
pub mod macros;

/// Module handling pmacct-compatible logging from pmacct-gauze
pub mod log;

#[cfg(test)]
pub mod tests {}
