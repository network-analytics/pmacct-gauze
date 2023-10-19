use std::convert::Infallible;
use std::error::Error;
use std::ffi::CString;
use std::fmt::{Display, Formatter};
use std::ops::{ControlFlow, FromResidual, Try};
use c_str_macro::c_str;
use crate::c_api::{ParseOk, ParseResultEnum};
use libc::c_char;

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", &self)
    }
}

impl Error for ParseError {}

impl FromResidual for ParseResultEnum {
    fn from_residual(residual: <Self as Try>::Residual) -> Self {
        match residual {
            Err(err) => ParseResultEnum::ParseFailure(err),
            _ => unreachable!("residual should always be the error")
        }
    }
}


#[repr(C)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ParseError {
    RouteDistinguisherError,
    IpAddrError,
    NetgauzeError(*mut c_char),
    StringConversionError,
}

impl ParseError {
    fn as_ptr(&self) -> *const c_char {
        match self {
            ParseError::RouteDistinguisherError => c_str! {
                "ParseError::RouteDistinguisherError"
            }.as_ptr(),
            ParseError::NetgauzeError(err) => {
                return *err as *const c_char;
            }
            ParseError::StringConversionError => c_str! {
                "ParseError::StringConversionError"
            }.as_ptr(),
            ParseError::IpAddrError => c_str! {
                "ParseError::IpAddrError"
            }.as_ptr(),
        }
    }
}
#[no_mangle]
pub extern "C" fn parse_error_str(error: &'static ParseError) -> *const c_char {
    error.as_ptr()
}

#[no_mangle]
pub extern "C" fn parse_result_free(value: ParseResultEnum) {
    match value {
        ParseResultEnum::ParseSuccess(parse_ok) => unsafe {
            drop(Box::from_raw(parse_ok.message));
        }
        ParseResultEnum::ParseFailure(parse_error) => {
            match parse_error {
                ParseError::NetgauzeError(err) => unsafe {
                    drop(CString::from_raw(err));
                },
                ParseError::RouteDistinguisherError
                | ParseError::StringConversionError
                | ParseError::IpAddrError => {}
            }
        }
    };
}
impl Try for ParseResultEnum {
    /// [Self::ParseSuccess]
    type Output = Self;

    /// Result<Infallible, ParseError>
    type Residual = Result<Infallible, ParseError>;

    fn from_output(output: Self::Output) -> Self {
        output
    }

    fn branch(self) -> ControlFlow<Self::Residual, Self::Output> {
        match self {
            ParseResultEnum::ParseSuccess(_) => ControlFlow::Continue(self),
            ParseResultEnum::ParseFailure(err) => ControlFlow::Break(Err(err))
        }
    }
}

impl From<ParseOk> for ParseResultEnum {
    fn from(value: ParseOk) -> Self {
        Self::ParseSuccess(value)
    }
}

impl From<ParseError> for ParseResultEnum {
    fn from(value: ParseError) -> Self {
        Self::ParseFailure(value)
    }
}
