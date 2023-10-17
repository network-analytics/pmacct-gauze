#![feature(try_trait_v2)]

pub(crate) mod extensions;

#[cfg(feature = "capi")]
pub mod c_api;

#[cfg(test)]
mod tests {

    #[test]
    fn test() {}
}
