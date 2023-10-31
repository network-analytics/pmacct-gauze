use core::mem::size_of;

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

    pub fn rust_free(self) {
        unsafe {
            drop(Vec::from_raw_parts(self.base_ptr, self.len, self.cap));
        }
    }
}