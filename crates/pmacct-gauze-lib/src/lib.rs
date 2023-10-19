#![feature(try_trait_v2)]
#![feature(vec_into_raw_parts)]
#![feature(ptr_metadata)]

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

#[cfg(test)]
mod tests {

    #[test]
    fn test() {}
}