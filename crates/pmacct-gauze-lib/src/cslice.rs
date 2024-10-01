use core::mem::size_of;
use std::mem::ManuallyDrop;
use std::ptr;

/// [CSlice<T>] represents a contiguous chunk of memory like an array.
#[repr(C)]
#[derive(Debug)]
pub struct CSlice<T> {
    pub base_ptr: *mut T,
    pub stride: usize,
    pub end_ptr: *mut T,
    pub len: usize,
    pub cap: usize,
}

/// Custom [Drop] trait to ensure correct behaviour with [CSlice::rust_free]
///
/// This trait is the equivalent of [Drop] but for Rust allocated items
/// that are not tracked anymore ([Box::into_raw], [Vec::into_raw]) or need
/// special treatment (a struct containing a raw [ptr] for example).
///
/// We do not use drop because it is implemented by default for all types,
/// and we want to make sure we never forget to implement [RustFree]
pub trait RustFree {
    fn rust_free(self);
}

impl<T> RustFree for CSlice<T>
where
    T: RustFree,
{
    fn rust_free(self) {
        let vec = unsafe { self.to_vec() };
        for item in vec {
            T::rust_free(item);
        }
    }
}

impl<T> CSlice<T> {
    /// Turn a [Vec<T>] into a [CSlice<T>] to send it over to C
    pub fn from_vec(value: Vec<T>) -> Self {
        // TODO replace by [Vec::into_raw_parts] when the vec_into_raw_parts feature is stable
        let mut value = ManuallyDrop::new(value);
        let (ptr, len, cap) = (value.as_mut_ptr(), value.len(), value.capacity());
        CSlice {
            base_ptr: ptr,
            stride: size_of::<T>(),
            end_ptr: unsafe { ptr.add(len) }, // this is guaranteed by [Vec::into_raw_parts]
            len,
            cap,
        }
    }

    /// Turn a [CSlice<T>] back into a [Vec<T>]
    /// # Safety
    /// see [Vec::from_raw_parts]
    pub unsafe fn to_vec(self) -> Vec<T> {
        Vec::from_raw_parts(self.base_ptr, self.len, self.cap)
    }

    pub fn dummy() -> Self {
        Self {
            base_ptr: ptr::null_mut(),
            stride: 0,
            end_ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}
