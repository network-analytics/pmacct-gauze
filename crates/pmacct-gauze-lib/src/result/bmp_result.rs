use crate::capi::bmp::ParsedBmp;
use crate::result::cresult::CResult;
use c_str_macro::c_str;
use libc::c_char;
use netgauze_bgp_pkt::wire::serializer::nlri::RouteDistinguisherWritingError;
use netgauze_bgp_pkt::wire::serializer::IpAddrWritingError;
use netgauze_bmp_pkt::iana::BmpMessageType;
use std::error::Error;
use std::ffi::CString;
use std::fmt::{Display, Formatter};

pub type BmpParseResult = CResult<ParsedBmp, BmpParseError>;

#[repr(C)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BmpParseError {
    RouteDistinguisher,
    IpAddr,
    NetgauzeBmpError(*mut c_char),
    StringConversion,
    WrongBmpMessageType(WrongBmpMessageTypeError),
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
            BmpParseError::WrongBmpMessageType(_) => c_str! {
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

impl From<RouteDistinguisherWritingError> for BmpParseError {
    fn from(_: RouteDistinguisherWritingError) -> Self {
        Self::RouteDistinguisher
    }
}

impl From<IpAddrWritingError> for BmpParseError {
    fn from(_: IpAddrWritingError) -> Self {
        Self::IpAddr
    }
}

#[no_mangle]
pub extern "C" fn bmp_parse_error_str(error: BmpParseError) -> *const c_char {
    error.as_str_ptr()
}

#[no_mangle]
pub extern "C" fn bmp_parse_result_free(value: BmpParseResult) {
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
            | BmpParseError::WrongBmpMessageType(_) => {}
        },
    };
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct WrongBmpMessageTypeError(pub u8);

impl From<BmpMessageType> for WrongBmpMessageTypeError {
    fn from(value: BmpMessageType) -> Self {
        Self(value.into())
    }
}

impl Display for WrongBmpMessageTypeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for WrongBmpMessageTypeError {}

impl<T> From<WrongBmpMessageTypeError> for CResult<T, WrongBmpMessageTypeError> {
    fn from(value: WrongBmpMessageTypeError) -> Self {
        Self::Err(value)
    }
}
