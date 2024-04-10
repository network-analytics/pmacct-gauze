#![feature(try_trait_v2)]
#![feature(vec_into_raw_parts)]
#![feature(ip_bits)]

// TODO make type Opaque<T> for opaque value with default helper methods
// TODO add annotations to specify which *mut pointers are consumed or not
// TODO add testing that validates return values using C functions
// TODO derive macro for automatic c function print for structs/enums implementation
// TODO consider removing some CResult when the msg type can be assumed as function contract for example

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

#[inline]
pub fn drop_rust_raw_box<T>(pointer: *mut T) {
    unsafe { drop(Box::from_raw(pointer)) }
}

#[inline]
pub fn make_rust_raw_box_pointer<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

#[cfg(test)]
pub mod tests {}
