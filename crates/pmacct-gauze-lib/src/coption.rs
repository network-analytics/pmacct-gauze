/// Re-implementation of [Option] but FFI compatible
#[repr(C)]
#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum COption<T> {
    None,
    Some(T),
}

impl<T> From<COption<T>> for Option<T> {
    fn from(value: COption<T>) -> Self {
        match value {
            COption::None => None,
            COption::Some(t) => Some(t),
        }
    }
}

impl<T> From<Option<T>> for COption<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            None => COption::None,
            Some(t) => COption::Some(t),
        }
    }
}
