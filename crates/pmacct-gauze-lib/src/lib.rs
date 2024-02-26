#![feature(try_trait_v2)]
#![feature(vec_into_raw_parts)]
#![feature(ptr_metadata)]
#![feature(ip_bits)]
#![feature(offset_of)]

// TODO add testing that validates return values using C functions

#[cfg(feature = "capi")]
pub mod capi;
#[cfg(feature = "capi")]
pub mod coption;
#[cfg(feature = "capi")]
pub mod cresult;
#[cfg(feature = "capi")]
pub mod extensions;
#[cfg(feature = "capi")]
pub mod slice;

#[macro_use]
pub mod macros;

#[cfg(feature = "capi")]
pub mod log;

#[cfg(test)]
pub mod tests {}
