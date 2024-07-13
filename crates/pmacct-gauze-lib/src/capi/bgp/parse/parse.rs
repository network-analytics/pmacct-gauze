use std::error::Error;
use std::ffi::CString;
use std::fmt::{Display, Formatter};
use std::slice;

use c_str_macro::c_str;
use libc::c_char;
use netgauze_bgp_pkt::BgpMessage;
use netgauze_bgp_pkt::wire::deserializer::{BgpMessageParsingError, BgpParsingContext};
use netgauze_parse_utils::{LocatedParsingError, ReadablePduWithOneInput, Span, WritablePdu};
use nom::Err;
use nom::Offset;

use pmacct_gauze_bindings::{bgp_header, BGP_NOTIFY_HEADER_ERR, BGP_NOTIFY_OPEN_ERR, BGP_NOTIFY_UPDATE_ERR, ERR, SUCCESS};

use crate::{drop_rust_raw_box, make_rust_raw_box_pointer};
use crate::cresult::CResult;
use crate::opaque::Opaque;

#[repr(C)]
#[derive(Debug)]
pub enum BgpParseError {
    NetgauzeBgpError {
        pmacct_error_code: i32,
        err_str: *mut c_char,
    },
    StringConversionError,
}

/// This structure must be freed using [bgp_parse_result_free]
pub type BgpParseResult = CResult<ParsedBgp, BgpParseError>;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct ParsedBgp {
    read_bytes: u32,
    pub header: bgp_header,
    pub message: *mut Opaque<BgpMessage>,
}

#[allow(clippy::not_unsafe_ptr_arg_deref)] // The pointer is not null by contract
#[no_mangle]
pub extern "C" fn netgauze_bgp_parse_packet(
    buffer: *const c_char,
    buffer_length: u32) -> BgpParseResult {
    netgauze_bgp_parse_packet_with_context(buffer, buffer_length, &mut Default::default())
}

#[no_mangle]
pub extern "C" fn netgauze_bgp_parse_packet_with_context(
    buffer: *const c_char,
    buffer_length: u32,
    bgp_parsing_context: *mut Opaque<BgpParsingContext>,
) -> BgpParseResult {
    let bgp_parsing_context = unsafe { bgp_parsing_context.as_mut().unwrap().as_mut() };

    let slice = unsafe { slice::from_raw_parts(buffer as *const u8, buffer_length as usize) };
    let span = Span::new(slice);
    let result = BgpMessage::from_wire(span, bgp_parsing_context);
    if let Ok((end_span, msg)) = result {
        let read_bytes = span.offset(&end_span) as u32;

        let result = CResult::Ok(ParsedBgp {
            read_bytes,
            header: bgp_header {
                bgpo_marker: [0xFF; 16],
                bgpo_len: msg.len() as u16,
                bgpo_type: msg.get_type() as u8,
            },
            message: make_rust_raw_box_pointer(Opaque::from(msg)),
        });

        return result;
    }

    let err = result.err().unwrap();
    // TODO special EoF error

    let err_code = {
        let err_map = |err: &BgpMessageParsingError| {
            match err {
                // NomError is probably just an EoF. Don't panic.
                BgpMessageParsingError::NomError(_)
                // Route Refresh is Ignored in pmacct. Ignore errors on them.
                | BgpMessageParsingError::BgpRouteRefreshMessageParsingError(_) => SUCCESS as i32,
                BgpMessageParsingError::ConnectionNotSynchronized(_)
                | BgpMessageParsingError::UndefinedBgpMessageType(_)
                | BgpMessageParsingError::BadMessageLength(_) => BGP_NOTIFY_HEADER_ERR as i32,
                BgpMessageParsingError::BgpOpenMessageParsingError(_) => BGP_NOTIFY_OPEN_ERR as i32,
                BgpMessageParsingError::BgpUpdateMessageParsingError(_) => BGP_NOTIFY_UPDATE_ERR as i32,
                BgpMessageParsingError::BgpNotificationMessageParsingError(_) => ERR,
            }
        };

        match &err {
            Err::Incomplete(_) => 0,
            Err::Error(err)
            | Err::Failure(err) => err_map(err.error()),
        }
    };

    let netgauze_error = match CString::new(err.to_string()) {
        Ok(str) => str,
        Err(_) => return BgpParseError::StringConversionError.into(),
    };

    BgpParseError::NetgauzeBgpError {
        pmacct_error_code: err_code,
        err_str: netgauze_error.into_raw(),
    }.into()
}

#[no_mangle]
pub extern "C" fn netgauze_bgp_parse_error_str(error: BgpParseError) -> *const c_char {
    error.as_str_ptr()
}

#[no_mangle]
pub extern "C" fn netgauze_bgp_parse_result_free(value: BgpParseResult) {
    match value {
        CResult::Ok(parse_ok) => {
            drop_rust_raw_box(parse_ok.message);
        }
        CResult::Err(parse_error) => match parse_error {
            BgpParseError::NetgauzeBgpError { err_str, .. } => unsafe {
                drop(CString::from_raw(err_str));
            },
            BgpParseError::StringConversionError => {}
        },
    };
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
            BgpParseError::NetgauzeBgpError { err_str, .. } => *err_str as *const c_char,
            BgpParseError::StringConversionError => c_str! {
                "BgpParseError::StringConversionError"
            }
                .as_ptr(),
        }
    }
}

impl<T> From<BgpParseError> for CResult<T, BgpParseError> {
    fn from(value: BgpParseError) -> Self {
        Self::Err(value)
    }
}
