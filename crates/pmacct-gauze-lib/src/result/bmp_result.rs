use crate::capi::bmp::ParsedBmp;
use crate::result::cresult::CResult;
use c_str_macro::c_str;
use libc::c_char;
use std::error::Error;
use std::ffi::CString;
use std::fmt::{Display, Formatter};

pub type BmpResult = CResult<ParsedBmp, BmpParseError>;

#[repr(C)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BmpParseError {
    RouteDistinguisher,
    IpAddr,
    NetgauzeBmpError(*mut c_char),
    StringConversion,
    WrongBmpMessageType,
}

impl Display for BmpParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", &self)
    }
}

impl Error for BmpParseError {}

impl BmpParseError {
    fn as_str_ptr(&self) -> *const c_char {
        match self {
            BmpParseError::RouteDistinguisher => c_str! {
                "BmpParseError::RouteDistinguisher"
            }
            .as_ptr(),
            BmpParseError::NetgauzeBmpError(err) => {
                return *err as *const c_char;
            }
            BmpParseError::StringConversion => c_str! {
                "BmpParseError::StringConversion"
            }
            .as_ptr(),
            BmpParseError::IpAddr => c_str! {
                "BmpParseError::IpAddr"
            }
            .as_ptr(),
            BmpParseError::WrongBmpMessageType => c_str! {
                "BmpParseError::WrongMessageType"
            }
            .as_ptr(),
        }
    }
}

impl<T> From<BmpParseError> for CResult<T, BmpParseError> {
    fn from(value: BmpParseError) -> Self {
        Self::Err(value)
    }
}

#[no_mangle]
pub extern "C" fn bmp_error_str(error: BmpParseError) -> *const c_char {
    error.as_str_ptr()
}

#[no_mangle]
pub extern "C" fn bmp_result_free(value: BmpResult) {
    match value {
        CResult::Ok(parse_ok) => unsafe {
            drop(Box::from_raw(parse_ok.message));
        },
        CResult::Err(parse_error) => match parse_error {
            BmpParseError::NetgauzeBmpError(err) => unsafe {
                drop(CString::from_raw(err));
            },
            BmpParseError::RouteDistinguisher
            | BmpParseError::StringConversion
            | BmpParseError::IpAddr
            | BmpParseError::WrongBmpMessageType => {}
        },
    };
}
