#![feature(try_trait_v2)]
#![feature(vec_into_raw_parts)]
#![feature(ptr_metadata)]
#![feature(ip_bits)]

// TODO use pmacct logger instead of println!
#[cfg(feature = "capi")]
pub(crate) mod extensions;
#[cfg(feature = "capi")]
pub mod c_api;
#[cfg(feature = "capi")]
pub mod option;
#[cfg(feature = "capi")]
pub mod error;
#[cfg(feature = "capi")]
pub mod slice;
#[macro_use]
pub mod macros;

pub mod debug;

#[cfg(test)]
mod tests {
    #[test]
    fn test() {}
}