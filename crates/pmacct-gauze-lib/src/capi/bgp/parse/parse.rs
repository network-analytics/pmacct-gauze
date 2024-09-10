use std::error::Error;
use std::ffi::CString;
use std::fmt::{Display, Formatter};
use std::slice;

use c_str_macro::c_str;
use libc::c_char;
use netgauze_bgp_pkt::wire::deserializer::BgpParsingContext;
use netgauze_bgp_pkt::BgpMessage;
use netgauze_parse_utils::{ReadablePduWithOneInput, Span};
use nom::Offset;

use crate::cresult::CResult;
use crate::opaque::Opaque;
use crate::{drop_rust_raw_box, make_rust_raw_box_pointer};

#[repr(C)]
#[derive(Debug)]
pub enum BgpParseError {
    NetgauzeBgpError(*mut c_char),
    StringConversionError,
}

/// This structure must be freed using [bgp_parse_result_free]
pub type BgpParseResult = CResult<ParsedBgp, BgpParseError>;

#[repr(C)]
pub struct ParsedBgp {
    read_bytes: u32,
    pub message: *mut Opaque<BgpMessage>,
}

#[no_mangle]
pub extern "C" fn netgauze_bgp_parse_packet(
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

        return CResult::Ok(ParsedBgp {
            read_bytes,
            message: make_rust_raw_box_pointer(Opaque::from(msg)),
        });
    }

    let err = result.err().unwrap();
    // TODO special EoF error

    let netgauze_error = match CString::new(err.to_string()) {
        Ok(str) => str,
        Err(_) => return BgpParseError::StringConversionError.into(),
    };

    BgpParseError::NetgauzeBgpError(netgauze_error.into_raw()).into()
}

#[no_mangle]
pub extern "C" fn bgp_parse_error_str(error: BgpParseError) -> *const c_char {
    error.as_str_ptr()
}

#[no_mangle]
pub extern "C" fn bgp_parse_result_free(value: BgpParseResult) {
    match value {
        CResult::Ok(parse_ok) => {
            drop_rust_raw_box(parse_ok.message);
        }
        CResult::Err(parse_error) => match parse_error {
            BgpParseError::NetgauzeBgpError(err) => unsafe {
                drop(CString::from_raw(err));
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
            BgpParseError::NetgauzeBgpError(err) => *err as *const c_char,
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
