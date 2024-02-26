use crate::capi::bmp::{BmpMessageValueOpaque, WrongBmpMessageTypeError};
use crate::coption::COption;
use crate::cresult::CResult;
use crate::extensions::bmp_message::ExtendBmpMessage;
use c_str_macro::c_str;
use libc::c_char;
use netgauze_bgp_pkt::wire::serializer::nlri::RouteDistinguisherWritingError;
use netgauze_bgp_pkt::wire::serializer::IpAddrWritingError;
use netgauze_bmp_pkt::BmpMessage;
use netgauze_parse_utils::{ReadablePduWithOneInput, Span};
use nom::Offset;
use pmacct_gauze_bindings::{bmp_common_hdr, bmp_peer_hdr};
use std::collections::HashMap;
use std::error::Error;
use std::ffi::CString;
use std::fmt::{Display, Formatter};
use std::slice;

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

#[repr(C)]
#[derive(Debug)]
pub struct ParsedBmp {
    read_bytes: u32,
    common_header: bmp_common_hdr,
    peer_header: COption<bmp_peer_hdr>,
    pub message: *mut BmpMessageValueOpaque,
}

#[no_mangle]
pub extern "C" fn netgauze_bmp_parse_packet(buffer: *const c_char, buf_len: u32) -> BmpParseResult {
    let s = unsafe { slice::from_raw_parts(buffer as *const u8, buf_len as usize) };
    let span = Span::new(s);
    let result = BmpMessage::from_wire(span, &mut HashMap::new());
    if let Ok((end_span, msg)) = result {
        let read_bytes = span.offset(&end_span) as u32;

        return BmpParseResult::Ok(ParsedBmp {
            read_bytes,
            common_header: bmp_common_hdr {
                version: msg.get_version().into(),
                len: read_bytes,
                type_: msg.get_type().into(),
            },
            peer_header: msg.get_pmacct_peer_hdr()?.into(),
            message: Box::into_raw(Box::new(match msg {
                BmpMessage::V3(value) => BmpMessageValueOpaque(value),
            })),
        });
    }

    let err = result.err().unwrap();
    // TODO special EoF error

    let netgauze_error = match CString::new(err.to_string()) {
        Ok(str) => str,
        Err(_) => return BmpParseError::StringConversion.into(),
    };

    BmpParseError::NetgauzeBmpError(netgauze_error.into_raw()).into()
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
