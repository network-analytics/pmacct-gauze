use core::mem::size_of;
use std::ptr;

#[repr(C)]
#[derive(Debug)]
pub struct CSlice<T> {
    pub base_ptr: *mut T,
    pub stride: usize,
    pub end_ptr: *mut T,
    pub len: usize,
    pub cap: usize,
}

impl<T> CSlice<T> {
    pub unsafe fn from_vec(value: Vec<T>) -> Self {
        let (ptr, len, cap) = value.into_raw_parts();
        CSlice {
            base_ptr: ptr,
            stride: size_of::<T>(),
            end_ptr: ptr.add(len),
            len,
            cap,
        }
    }

    pub unsafe fn to_vec(self) -> Vec<T> {
        Vec::from_raw_parts(self.base_ptr, self.len, self.cap)
    }

    pub fn rust_free(self) {
        unsafe {
            self.to_vec();
        }
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
