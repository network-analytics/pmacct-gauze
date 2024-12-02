use core::mem::size_of;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::{ptr, slice};
// TODO consider adding OwnedSlice / Slice or CSlice<Owned/Borrowed>

/// [`OwnedSlice<T>`] represents an owned contiguous chunk of memory like an array.
/// It must be manually freed by giving it back to Rust using CSlice_free_* functions.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct OwnedSlice<T> {
    pub base_ptr: *mut T,
    pub stride: usize,
    pub end_ptr: *mut T,
    pub len: usize,
    pub cap: usize,
}

/// Custom [Drop] trait to ensure correct behaviour with [OwnedSlice::rust_free]
///
/// This trait is the equivalent of [Drop] but for Rust allocated items
/// that are not tracked anymore ([Box::into_raw], [Vec::into_raw_parts]) or need
/// special treatment (a struct containing a raw [ptr] for example).
///
/// We do not use drop because it is implemented by default for all types,
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
    /// Turn a [`Vec<T>`] into a [`OwnedSlice<T>`] to send it over to C
    pub fn from_vec(value: Vec<T>) -> Self {
        // TODO replace by [Vec::into_raw_parts] when the vec_into_raw_parts feature is stable
        let mut value = ManuallyDrop::new(value);
        let (ptr, len, cap) = (value.as_mut_ptr(), value.len(), value.capacity());
        OwnedSlice {
            base_ptr: ptr,
            stride: size_of::<T>(),
            end_ptr: unsafe { ptr.add(len) }, // this is guaranteed by [Vec::into_raw_parts]
            len,
            cap,
        }
    }

    /// Turn a [`OwnedSlice<T>`] back into a [`Vec<T>`]
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

    /// Make an [`OwnedSlice<T>`] from a slice [`&[T]`]
    pub fn from_slice(value: &[T]) -> Self {
        let (ptr, len) = (value.as_ptr(), value.len());
        Self {
            base_ptr: ptr as *mut T,
            stride: size_of::<T>(),
            end_ptr: unsafe { ptr.add(len) as *mut T },
            len,
            cap: len,
        }
    }

    /// Get a slice [`&[T]`] from [`OwnedSlice<T>`]
    /// # Safety
    /// see [slice::from_raw_parts]
    pub unsafe fn as_slice(&self) -> &[T] {
        slice::from_raw_parts(self.base_ptr, self.len)
    }

    /// Get a slice [`&mut [T]`] from [`OwnedSlice<T>`]
    /// # Safety
    /// see [slice::from_raw_parts_mut]
    pub unsafe fn to_slice_mut(&mut self) -> &mut [T] {
        slice::from_raw_parts_mut(self.base_ptr, self.len)
    }
}

/// [`BorrowedSlice<T>`] represents a borrowed contiguous chunk of memory like an array.
/// /!\ WARNING /!\
/// UNUSED AND NOT TESTED AT THE MOMENT
#[repr(C)]
#[derive(Debug, Clone)]
pub struct BorrowedSlice<'a, T> {
    pub base_ptr: *const T,
    pub stride: usize,
    pub end_ptr: *const T,
    pub len: usize,
    pub cap: usize,
    _marker: PhantomData<&'a T>,
}

impl<T> BorrowedSlice<'_, T> {
    /// Turn a [`Vec<T>`] into a [`BorrowedSlice<'a, T>`] to send it over to C
    /// # Safety
    /// The [`Vec<T>`] must not be freed before the [`BorrowedSlice<'a, T>`] is.
    pub fn from_vec(value: &Vec<T>) -> Self {
        // TODO replace by [Vec::into_raw_parts] when the vec_into_raw_parts feature is stable
        let (ptr, len, cap) = (value.as_ptr(), value.len(), value.capacity());
        Self {
            base_ptr: ptr,
            stride: size_of::<T>(),
            end_ptr: unsafe { ptr.add(len) },
            len,
            cap,
            _marker: Default::default(),
        }
    }

    pub fn dummy() -> Self {
        Self {
            base_ptr: ptr::null(),
            stride: 0,
            end_ptr: ptr::null(),
            len: 0,
            cap: 0,
            _marker: Default::default(),
        }
    }

    /// Make an [`OwnedSlice<T>`] from [`&[T]`]
    pub fn from_slice(value: &[T]) -> Self {
        let (ptr, len) = (value.as_ptr(), value.len());
        Self {
            base_ptr: ptr as *mut T,
            stride: size_of::<T>(),
            end_ptr: unsafe { ptr.add(len) as *mut T },
            len,
            cap: len,
            _marker: Default::default(),
        }
    }

    /// Make a slice [`&[T]`] from [`OwnedSlice<T>`]
    /// # Safety
    /// see [slice::from_raw_parts]
    pub unsafe fn as_slice(&self) -> &[T] {
        slice::from_raw_parts(self.base_ptr, self.len)
    }
}
