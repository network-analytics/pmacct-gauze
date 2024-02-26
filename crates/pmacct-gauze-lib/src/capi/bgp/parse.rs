use crate::capi::bgp::BgpMessageOpaque;
use crate::cresult::CResult;
use crate::extensions::add_path::AddPathCapability;
use c_str_macro::c_str;
use libc::c_char;
use netgauze_bgp_pkt::wire::deserializer::BgpParsingContext;
use netgauze_bgp_pkt::BgpMessage;
use netgauze_parse_utils::{ReadablePduWithOneInput, Span};
use nom::Offset;
use pmacct_gauze_bindings::{afi_t, cap_per_af, safi_t};
use std::error::Error;
use std::ffi::CString;
use std::fmt::{Display, Formatter};
use std::slice;

#[repr(C)]
#[derive(Debug)]
pub enum BgpParseError {
    NetgauzeBgpError(*mut c_char),
    StringConversionError,
}

pub type BgpParseResult = CResult<ParsedBgp, BgpParseError>;

#[repr(C)]
pub struct ParsedBgp {
    read_bytes: u32,
    pub message: *mut BgpMessageOpaque,
}

pub struct BgpParsingContextOpaque(BgpParsingContext);

#[repr(C)]
pub struct UnsupportedAfiSafi {
    afi: afi_t,
    safi: safi_t,
}

pub type BgpParsingContextResult = CResult<*mut BgpParsingContextOpaque, UnsupportedAfiSafi>;

#[no_mangle]
pub extern "C" fn netgauze_make_bgp_parsing_context(
    asn4: bool,
    add_path: *const cap_per_af,
    fail_on_non_unicast_withdraw_nlri: bool,
    fail_on_non_unicast_update_nlri: bool,
    fail_on_capability_error: bool,
    fail_on_malformed_path_attr: bool,
) -> BgpParsingContextResult {
    let add_path = unsafe { add_path.as_ref().unwrap() };
    let add_path = add_path.get_receive_map();
    let add_path = if let Ok(map) = add_path {
        map
    } else {
        let (afi, safi) = add_path.err().unwrap();
        return Err(UnsupportedAfiSafi { afi, safi }).into();
    };

    Ok(Box::into_raw(Box::new(BgpParsingContextOpaque(
        BgpParsingContext::new(
            asn4,
            Default::default(), // pmacct: this is not supported in pmacct
            add_path,
            fail_on_non_unicast_withdraw_nlri,
            fail_on_non_unicast_update_nlri,
            fail_on_capability_error,
            fail_on_malformed_path_attr,
        ),
    ))))
    .into()
}

#[no_mangle]
pub extern "C" fn netgauze_free_bgp_parsing_context(
    bgp_parsing_context_opaque: *mut BgpParsingContextOpaque,
) {
    unsafe { drop(Box::from_raw(bgp_parsing_context_opaque)) }
}

#[no_mangle]
pub extern "C" fn netgauze_bgp_parse_packet(
    buffer: *const libc::c_char,
    buffer_length: u32,
    bgp_parsing_context: *mut BgpParsingContextOpaque,
) -> BgpParseResult {
    let bgp_parsing_context = unsafe {
        (bgp_parsing_context as *mut BgpParsingContext)
            .as_mut()
            .unwrap()
    };

    let slice = unsafe { slice::from_raw_parts(buffer as *const u8, buffer_length as usize) };
    let span = Span::new(slice);
    let result = BgpMessage::from_wire(span, bgp_parsing_context);
    if let Ok((end_span, msg)) = result {
        let read_bytes = span.offset(&end_span) as u32;

        return CResult::Ok(ParsedBgp {
            read_bytes,
            message: Box::into_raw(Box::new(BgpMessageOpaque(msg))),
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
        CResult::Ok(parse_ok) => unsafe {
            drop(Box::from_raw(parse_ok.message));
        },
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
            BgpParseError::NetgauzeBgpError(err) => {
                return *err as *const c_char;
            }
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
