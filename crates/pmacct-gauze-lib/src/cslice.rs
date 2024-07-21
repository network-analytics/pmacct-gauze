use core::mem::size_of;
use std::{ptr, slice};

// TODO consider adding OwnedSlice / Slice or CSlice<Owned/Borrowed>

/// [OwnedSlice<T>] represents an owned contiguous chunk of memory like an array.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct OwnedSlice<T> {
    pub base_ptr: *mut T,
    pub stride: usize,
    pub end_ptr: *mut T,
    pub len: usize,
    pub cap: usize,
}

/// This trait is the equivalent of [Drop] but for Rust allocated items
/// that are not tracked anymore ([Box::into_raw], [Vec::into_raw]) or need
/// special treatment (a struct containing a raw [ptr] for example).
///
/// We do not use drop because it is implemented by default for all types
/// and we want to make sure we never forget to implement [RustFree]
pub trait RustFree {
    fn rust_free(self);
}

impl<T> RustFree for OwnedSlice<T>
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

impl<T> OwnedSlice<T> {
    /// Turn a [Vec<T>] into a [OwnedSlice<T>] to send it over to C
    pub unsafe fn from_vec(value: Vec<T>) -> Self {
        let (ptr, len, cap) = value.into_raw_parts();
        Self {
            base_ptr: ptr,
            stride: size_of::<T>(),
            end_ptr: ptr.add(len),
            len,
            cap,
        }
    }

    /// Turn a [OwnedSlice<T>] back into a [Vec<T>]
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

    pub unsafe fn from_slice(value: &[T]) -> Self {
        let (ptr, len) = (value.as_ptr(), value.len());
        Self {
            base_ptr: ptr as *mut T,
            stride: size_of::<T>(),
            end_ptr: ptr.add(len) as *mut T,
            len,
            cap: len,
        }
    }

    pub unsafe fn to_slice<'a>(value: Self) -> &'a [T] {
        slice::from_raw_parts(value.base_ptr, value.len)
    }

    pub unsafe fn to_slice_mut<'a>(value: Self) -> &'a mut [T] {
        slice::from_raw_parts_mut(value.base_ptr, value.len)
    }
}


/// [BorrowedSlice<T>] represents a borrowed contiguous chunk of memory like an array.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct BorrowedSlice<T> {
    pub base_ptr: *const T,
    pub stride: usize,
    pub end_ptr: *const T,
    pub len: usize,
    pub cap: usize,
}

impl<T> BorrowedSlice<T> {
    /// Turn a [Vec<T>] into a [BorrowedSlice<T>] to send it over to C
    pub unsafe fn from_vec(value: &Vec<T>) -> Self {
        let (ptr, len, cap) = (value.as_ptr(), value.len(), value.capacity());
        Self {
            base_ptr: ptr,
            stride: size_of::<T>(),
            end_ptr: ptr.add(len),
            len,
            cap,
        }
    }

    pub fn dummy() -> Self {
        Self {
            base_ptr: ptr::null(),
            stride: 0,
            end_ptr: ptr::null(),
            len: 0,
            cap: 0,
        }
    }

    pub unsafe fn from_slice(value: &[T]) -> Self {
        let (ptr, len) = (value.as_ptr(), value.len());
        Self {
            base_ptr: ptr as *mut T,
            stride: size_of::<T>(),
            end_ptr: ptr.add(len) as *mut T,
            len,
            cap: len,
        }
    }

    pub unsafe fn to_slice<'a>(value: Self) -> &'a [T] {
        slice::from_raw_parts(value.base_ptr, value.len)
    }

    pub unsafe fn to_slice_mut<'a>(value: Self) -> &'a mut [T] {
        slice::from_raw_parts_mut(value.base_ptr as *mut T, value.len)
    }
}