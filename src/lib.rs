#[cfg(feature = "capi")]
pub mod c_api;

#[cfg(feature = "source-bindings")]
pub mod bindings;

#[cfg(not(feature = "source-bindings"))]
pub mod bindings {
    // Include the generated bindings
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[cfg(test)]
mod tests {

    #[test]
    fn test() {}
}
