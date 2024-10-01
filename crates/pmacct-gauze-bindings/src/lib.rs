#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub use bindings::*;

pub mod convert;
pub mod print;

/// Impl this trait on a struct to make zeroed values of the struct
/// Useful for initializing complex C structs quickly
///
/// # Safety
/// see the [std::mem::zeroed] safety section and if it applies to the struct you are impl-ing this on
pub trait DefaultZeroed: Sized {
    fn default_zeroed() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// This module is generated by `build.rs` in the build directory
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
