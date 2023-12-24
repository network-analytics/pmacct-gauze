use std::convert::Infallible;
use std::ops::{ControlFlow, FromResidual, Try};

#[repr(C)]
#[derive(Debug)]
pub enum CResult<S, E> {
    Ok(S),
    Err(E),
}

impl<T, E> FromResidual for CResult<T, E> {
    fn from_residual(residual: <Self as Try>::Residual) -> Self {
        match residual {
            Err(err) => CResult::Err(err),
            _ => unreachable!("residual should always be the error")
        }
    }
}

impl<T, E> Try for CResult<T, E> {
    /// [Self::Ok]
    type Output = Self;

    /// Result<Infallible, ParseError>
    type Residual = Result<Infallible, E>;

    fn from_output(output: Self::Output) -> Self {
        output
    }

    fn branch(self) -> ControlFlow<Self::Residual, Self::Output> {
        match self {
            CResult::Ok(_) => ControlFlow::Continue(self),
            CResult::Err(err) => ControlFlow::Break(Err(err))
        }
    }
}