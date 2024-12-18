use std::error::Error;
use std::ffi::CString;
use std::fmt::{Display, Formatter};
use std::slice;

use c_str_macro::c_str;
use libc::c_char;
use netgauze_bgp_pkt::wire::serializer::nlri::RouteDistinguisherWritingError;
use netgauze_bgp_pkt::wire::serializer::IpAddrWritingError;
use netgauze_bmp_pkt::wire::deserializer::BmpParsingContext;
use netgauze_bmp_pkt::{BmpMessage, BmpMessageValue};
use netgauze_parse_utils::{ReadablePduWithOneInput, Span};
use nom::Offset;

use pmacct_gauze_bindings::{bmp_common_hdr, bmp_peer_hdr};

use crate::capi::bmp::WrongBmpMessageTypeError;
use crate::coption::COption;
use crate::cresult::CResult;
use crate::extensions::bmp_message::ExtendBmpMessage;
use crate::opaque::Opaque;
use crate::{drop_rust_raw_box, make_rust_raw_box_pointer};

/// This structure must be manually freed using [bmp_parse_result_free]
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
    pub message: *mut Opaque<BmpMessageValue>,
}

/// Parse a [BmpMessage] from a buffer with given length without context
///
/// # Safety
/// `buffer` should be not null and point to valid data of length `buf_len`
/// `bmp_parsing_context` should be not null and point to valid data
///
/// This function does not consume the `bmp_parsing_context` pointer
#[no_mangle]
pub unsafe extern "C" fn netgauze_bmp_parse_packet(
    buffer: *const c_char,
    buf_len: u32,
) -> BmpParseResult {
    let ctx = BmpParsingContext::default();
    netgauze_bmp_parse_packet_with_context(buffer, buf_len, &mut Opaque::from(ctx))
}

/// Parse a [BmpMessage] from a buffer with given length using a given context
///
/// # Safety
/// `buffer` should be not null and point to valid data of length `buf_len`
/// `bmp_parsing_context` should be not null and point to valid data
///
/// This function does not consume the `bmp_parsing_context` pointer
#[no_mangle]
pub unsafe extern "C" fn netgauze_bmp_parse_packet_with_context(
    buffer: *const c_char,
    buf_len: u32,
    bmp_parsing_context: *mut Opaque<BmpParsingContext>,
) -> BmpParseResult {
    let s = unsafe { slice::from_raw_parts(buffer as *const u8, buf_len as usize) };
    let span = Span::new(s);

    let bmp_parsing_context = unsafe { bmp_parsing_context.as_mut().unwrap() };

    let result = BmpMessage::from_wire(span, &mut bmp_parsing_context.as_mut());
    if let Ok((end_span, msg)) = result {
        let read_bytes = span.offset(&end_span) as u32;

        bmp_parsing_context.as_mut().update(&msg);

        return BmpParseResult::Ok(ParsedBmp {
            read_bytes,
            common_header: bmp_common_hdr {
                version: msg.get_version().into(),
                len: read_bytes,
                type_: msg.get_type().into(),
            },
            peer_header: match msg.get_pmacct_peer_hdr() {
                Ok(ok) => ok.into(),
                Err(err) => return CResult::Err(err),
            },
            message: make_rust_raw_box_pointer(match msg {
                BmpMessage::V3(value) => Opaque::from(value),
            }),
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
            BmpParseError::NetgauzeBmpError(err) => *err as *const c_char,
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
pub extern "C" fn netgauze_bmp_parse_error_str(error: BmpParseError) -> *const c_char {
    error.as_str_ptr()
}

#[no_mangle]
pub extern "C" fn netgauze_bmp_parse_result_free(value: BmpParseResult) {
    match value {
        CResult::Ok(parse_ok) => {
            drop_rust_raw_box(parse_ok.message);
        }
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
