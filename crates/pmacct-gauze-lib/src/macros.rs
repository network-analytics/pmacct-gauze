pub use paste;

#[macro_export]
macro_rules! free_cslice_t {
    ($typ:ty) => {
        crate::macros::paste::paste! {
            #[no_mangle]
            pub extern "C" fn  [< CSlice_free_ $typ >] (slice: CSlice<$typ>) {
                unsafe {
                    drop(Vec::from_raw_parts(slice.base_ptr, slice.len, slice.cap));
                }
            }
        }
    };
}
pub use free_cslice_t;


// TODO qol: derive macro with automatic rust_free impl
#[macro_export]
macro_rules! free_cslice_t_with_item_free {
    ($typ:ty) => {
        crate::macros::paste::paste! {
            #[no_mangle]
            pub extern "C" fn  [< CSlice_free_ $typ >] (slice: CSlice<$typ>) {
                unsafe {
                    let vec = Vec::from_raw_parts(slice.base_ptr, slice.len, slice.cap);
                    for item in vec {
                        $typ :: rust_free(item)
                    }
                    drop(vec);
                }
            }
        }
    };
}
pub use free_cslice_t_with_item_free;