use std::convert::Infallible;
use std::ops::{ControlFlow, FromResidual, Try};

/// Re-implementation of [Result] but FFI compatible
#[repr(C)]
#[derive(Debug, Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum CResult<S, E> {
    Ok(S),
    Err(E),
}

impl<T, E> FromResidual for CResult<T, E> {
    fn from_residual(residual: <Self as Try>::Residual) -> Self {
        match residual {
            Err(err) => CResult::Err(err),
        }
    }
}

impl<T, E> Try for CResult<T, E> {
    /// [Self::Ok]
    type Output = Self;

    type Residual = Result<Infallible, E>;

    fn from_output(output: Self::Output) -> Self {
        output
    }

    fn branch(self) -> ControlFlow<Self::Residual, Self::Output> {
        match self {
            CResult::Ok(_) => ControlFlow::Continue(self),
            CResult::Err(err) => ControlFlow::Break(Err(err)),
        }
    }
}

impl<T, E> From<Result<T, E>> for CResult<T, E> {
    fn from(value: Result<T, E>) -> Self {
        match value {
            Ok(ok) => Self::Ok(ok),
            Err(err) => Self::Err(err),
        }
    }
}
