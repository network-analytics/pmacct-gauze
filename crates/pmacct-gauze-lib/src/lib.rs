#![feature(try_trait_v2)]
#![feature(vec_into_raw_parts)]

#[cfg(feature = "capi")]
pub(crate) mod extensions;

#[cfg(feature = "capi")]
pub mod c_api;

#[cfg(test)]
mod tests {

    #[test]
    fn test() {}
}
