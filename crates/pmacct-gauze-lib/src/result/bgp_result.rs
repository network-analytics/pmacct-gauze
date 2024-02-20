use crate::capi::bgp::BgpParseResult;
use crate::result::cresult::CResult;
use libc::c_char;
use std::error::Error;
use std::ffi::CString;
use std::fmt::{Display, Formatter};

#[repr(C)]
#[derive(Debug)]
pub enum BgpUpdateError {
    WrongBgpMessageType,
}

impl<T> From<BgpUpdateError> for CResult<T, BgpUpdateError> {
    fn from(value: BgpUpdateError) -> Self {
        CResult::Err(value)
    }
}

impl Display for BgpUpdateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for BgpUpdateError {}

#[repr(C)]
#[derive(Debug)]
pub enum BgpParseError {
    NetgauzeBgpError(*mut c_char),
}

impl Display for BgpParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for BgpParseError {}
impl BgpParseError {
    fn as_str_ptr(&self) -> *const c_char {
        match self {
            BgpParseError::NetgauzeBgpError(err) => {
                return *err as *const c_char;
            }
        }
    }
}

impl<T> From<BgpParseError> for CResult<T, BgpParseError> {
    fn from(value: BgpParseError) -> Self {
        Self::Err(value)
    }
}
#[no_mangle]
pub extern "C" fn bgp_parse_error_str(error: BgpParseError) -> *const c_char {
    error.as_str_ptr()
}

#[no_mangle]
pub extern "C" fn bgp_parse_result_free(value: BgpParseResult) {
    match value {
        CResult::Ok(parse_ok) => unsafe {
            drop(Box::from_raw(parse_ok.message));
        },
        CResult::Err(parse_error) => match parse_error {
            BgpParseError::NetgauzeBgpError(err) => unsafe {
                drop(CString::from_raw(err));
            },
        },
    };
}
