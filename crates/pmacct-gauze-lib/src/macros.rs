pub use paste;

/// Generate a function called `CSlice_free_T` for C to free a [`crate::cslice::CSlice<T>`] for type `T`.
///
/// This variant of the macro automatically implements [crate::cslice::RustFree] for the type `T`
/// The automatic implementation for [crate::cslice::RustFree::rust_free] on `T` just drops the value
/// without specific behaviour.
///
/// If you want to customize the [crate::cslice::RustFree::rust_free] implementation,
/// look into [free_cslice_t_with_item_free]
///
/// If `T` has generic parameters, the macro can't use T to name the function automatically.
/// You will need to provide the function suffix as a 2nd parameter of the macro.
/// ```rust
/// use pmacct_gauze_lib::free_cslice_t;
/// use pmacct_gauze_lib::cslice::*;
/// struct SomeGenericStruct<T>(T);
/// /* free_cslice_t!(SomeGenericStruct<u16>); this can't work because
///  * CSlice_free_SomeGenericStruct<T> is not a valid function name
///  */
///
/// // This will work because CSlice_free_SomeGenericStruct_u16 is now a valid function name
/// free_cslice_t!(SomeGenericStruct<u16>, SomeGenericStruct_u16);
/// ```  
///
#[macro_export]
macro_rules! free_cslice_t {
    ($typ:ty, $name:ty) => {
        $crate::macros::paste::paste! {
            #[no_mangle]
            pub extern "C" fn  [< CSlice_free_ $name >] (slice: CSlice<$typ>) {
                CSlice::<$typ>::rust_free(slice);
            }
        }

        #[automatically_derived]
        impl $crate::cslice::RustFree for $typ {
            fn rust_free(self) {}
        }
    };
    ($typ:ty) => {
        $crate::macros::free_cslice_t!($typ, $typ);
    };
}
pub use free_cslice_t;

/// Generate a function called `CSlice_free_T` for C to free a [`crate::cslice::CSlice<T>`] for type `T`
///
/// This macro work exactly as the macro [free_cslice_t] works
/// without implementing [crate::cslice::RustFree] automatically for `T`.
///
/// This allows you to implement [crate::cslice::RustFree] for `T` if you need a special behaviour to free the type.
///
/// Example:
/// ```
/// use pmacct_gauze_lib::free_cslice_t_with_item_free;
/// use pmacct_gauze_lib::cslice::RustFree;
/// use pmacct_gauze_lib::cslice::CSlice;
/// struct Struct;
///
/// // This type is needed to be able to implement RustFree as we can't impl a foreign trait on arbitrary types
/// struct MutPtr<T>(*mut T);
///
/// free_cslice_t_with_item_free!(MutPtr<Struct>, MutPtr_Struct);
///
/// // This impl could impl for all T
/// impl RustFree for MutPtr<Struct> {
///     fn rust_free(self) {
///         if !self.0.is_null() {
///             unsafe {
///                 // Assuming this pointer was from a Box::into_raw. Do whatever you need to do here.
///                 let ptr: *mut Struct = self.0;
///                 drop(Box::from_raw(ptr));
///             }
///         }
///     }
/// }
/// ```
#[macro_export]
macro_rules! free_cslice_t_with_item_free {
    ($typ:ty, $name:ty) => {
        $crate::macros::paste::paste! {
            #[no_mangle]
            pub extern "C" fn  [< CSlice_free_ $name >] (slice: CSlice<$typ>) {
                CSlice :: <$typ> :: rust_free(slice);
            }
        }
    };
    ($typ:ty) => {
        $crate::macros::free_cslice_t_with_item_free!($typ, $typ);
    };
}
pub use free_cslice_t_with_item_free;

/// Generate a function called `netgauze_make_T` for C to allocate a [Default] value of `T` on the heap.
///
/// The generated function makes a [`Box::<T>`] and turns it into a raw pointer to give to C using [crate::make_rust_raw_box_pointer].
/// The second parameter is used to change the name of `T` in the generated function name.
/// It is mandatory if `T` itself is generic.
///
/// Example:
/// ```
/// use pmacct_gauze_lib::{make_default};
/// use pmacct_gauze_lib::cslice::RustFree;
/// use pmacct_gauze_lib::cslice::CSlice;
///
/// #[derive(Default)]
/// struct Data;
///
/// #[derive(Default)]
/// struct GenericStruct<S> {
///     inner: S,
/// }
///
/// make_default!(Data);
/// make_default!(GenericStruct<Data>, GenericStruct_Data);
/// ```
#[macro_export]
macro_rules! make_default {
    ($typ:ty, $name:ty) => {
        $crate::macros::paste::paste! {
            #[no_mangle]
            pub extern "C" fn  [< netgauze_make_ $name >] () -> *mut $typ {
                $crate::make_rust_raw_box_pointer(Default::default())
            }
        }
    };
    ($typ:ty) => {
        $crate::macros::make_default!($typ, $typ);
    };
}
pub use make_default;

/// Generate a function called `netgauze_free_T` for C to free a value of `T` from the heap.
///
/// The generated function takes a raw pointer [*mut T] made from a [`Box::<T>`], and drops it using [crate::drop_rust_raw_box].
/// The second parameter is used to change the name of `T` in the generated function name.
/// It is mandatory if `T` itself is generic.
///
/// Example:
/// ```
/// use pmacct_gauze_lib::{free_rust_raw_box};
/// use pmacct_gauze_lib::cslice::RustFree;
/// use pmacct_gauze_lib::cslice::CSlice;
/// struct Data;
/// struct GenericStruct<S> {
///     inner: S,
/// }
///
/// free_rust_raw_box!(Data);
/// free_rust_raw_box!(GenericStruct<Data>, GenericStruct_Data);
/// ```
#[macro_export]
macro_rules! free_rust_raw_box {
    ($typ:ty, $name:ty) => {
        $crate::macros::paste::paste! {
            #[allow(non_snake_case)]
            #[no_mangle]
            pub extern "C" fn  [< netgauze_free_ $name >] ( [< $name _pointer >] : *mut $typ ) {
                $crate::drop_rust_raw_box( [< $name _pointer >] )
            }
        }
    };
    ($typ:ty) => {
        $crate::macros::free_rust_raw_box!($typ, $typ);
    };
}
pub use free_rust_raw_box;
