/// Structure indicating that the contained type must be opaque to C.
/// This can only be passed to/from C as raw pointers.
///
/// Casting a raw pointer from/to *mut/const Opaque<T> to/from *mut/const T is safe
/// thanks to the new-type pattern guarantees
#[derive(Default, Debug, Clone)]
pub struct Opaque<T>(T);

impl<T> Opaque<T> {
    pub fn value(self) -> T {
        self.0
    }
}

impl<T> From<T> for Opaque<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> AsMut<T> for Opaque<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T> AsRef<T> for Opaque<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}
