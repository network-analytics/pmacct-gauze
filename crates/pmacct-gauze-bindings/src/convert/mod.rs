mod address_family;
pub mod ipaddr;
pub mod rd;
pub mod timeval;

/// Equivalent of From/Into and TryFrom/TryInto but this trait is owned by the crate so we can implement it on any type

pub trait ConvertFrom<T> {
    fn convert_from(value: T) -> Self;
}

pub trait ConvertTo<T> {
    fn convert_to(self) -> T;
}

impl<T, R> ConvertTo<T> for R
where
    T: ConvertFrom<R>,
{
    fn convert_to(self) -> T {
        T::convert_from(self)
    }
}

pub trait TryConvertFrom<T>: Sized {
    type Error;

    fn try_convert_from(value: T) -> Result<Self, Self::Error>;
}

pub trait TryConvertInto<T, E> {
    fn try_convert_to(self) -> Result<T, E>;
}

impl<T, TE, R> TryConvertInto<T, TE> for R
where
    T: TryConvertFrom<R, Error = TE>,
{
    fn try_convert_to(self) -> Result<T, TE> {
        T::try_convert_from(self)
    }
}
