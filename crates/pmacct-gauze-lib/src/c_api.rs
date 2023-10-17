use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::ffi::{c_char, c_void, CString};
use std::fmt::{Debug, Display, Formatter};
use std::mem::size_of;
use std::ops::{ControlFlow, FromResidual, Try};
use libc;
use netgauze_bmp_pkt::{BmpMessage, BmpMessageValue, InitiationInformation};
use netgauze_parse_utils::{Span, WritablePdu};
use nom::Offset;
use pmacct_gauze_bindings::{bmp_common_hdr, bmp_peer_hdr, bmp_log_tlv};
use netgauze_parse_utils::ReadablePduWithOneInput;
use std::slice;
use c_str_macro::c_str;
use crate::extensions::bmp_message::ExtendBmpMessage;
use crate::extensions::initiation_information::InitInfoExtend;

pub struct BmpMessageValueOpaque(BmpMessageValue);

#[no_mangle]
pub extern "C" fn netgauze_print_packet(buffer: *const libc::c_char, len: u32) -> u32 {

    let s = unsafe { slice::from_raw_parts(buffer as *const u8, len as usize) };
    let span = Span::new(s);
    if let Ok((end_span, msg)) = BmpMessage::from_wire(span, &HashMap::new()) {
        println!("span: ptr: {:?} | value {:?}", span.as_ptr(), span);
        println!("msg: {:?}", msg);
        return span.offset(&end_span) as u32;
    }

    0
}

#[repr(C)]
pub enum COption<T> {
    None,
    Some(T),
}

impl<T> From<COption<T>> for Option<T> {
    fn from(value: COption<T>) -> Self {
        match value {
            COption::None => None,
            COption::Some(t) => Some(t)
        }
    }
}

impl<T> From<Option<T>> for COption<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            None => COption::None,
            Some(t) => COption::Some(t)
        }
    }
}

#[repr(C)]
pub struct ParseOk {
    read_bytes: u32,
    common_header: bmp_common_hdr,
    peer_header: COption<bmp_peer_hdr>,
    message: *mut BmpMessageValueOpaque,
}

#[repr(C)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ParseError {
    MessageDoesNotHavePeerHeader,
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
            ParseError::MessageDoesNotHavePeerHeader => c_str! {
                "ParseError::MessageDoesNotHavePeerHeader"
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
            let _ = Box::from_raw(parse_ok.message);
        }
        ParseResultEnum::ParseFailure(parse_error) => {
            match parse_error {
                ParseError::MessageDoesNotHavePeerHeader => {}
                ParseError::RouteDistinguisherError => {}
                ParseError::NetgauzeError(err) => unsafe {
                    let _ = CString::from_raw(err);
                },
                ParseError::StringConversionError => {}
                ParseError::IpAddrError => {}
            }
        }
    };
}

#[repr(C)]
pub enum ParseResultEnum {
    ParseSuccess(ParseOk),
    ParseFailure(ParseError),
}

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

impl Try for ParseResultEnum {
    /// [Self::ParseSuccess]
    type Output = Self;

    /// [Self::ParseFailure]
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


#[no_mangle]
pub extern "C" fn netgauze_parse_packet(buffer: *const libc::c_char, buf_len: u32) -> ParseResultEnum {

    let s = unsafe { slice::from_raw_parts(buffer as *const u8, buf_len as usize) };
    let span = Span::new(s);
    let result = BmpMessage::from_wire(span, &HashMap::new());
    if let Ok((end_span, msg)) = result {
        let read_bytes = span.offset(&end_span) as u32;

        // println!("netgauze {} bytes read", read_bytes);

        return ParseResultEnum::ParseSuccess(ParseOk {
            read_bytes,
            common_header: bmp_common_hdr {
                version: msg.get_version().into(),
                len: read_bytes,
                type_: msg.get_type().into(),
            },
            peer_header: msg.get_pmacct_peer_hdr()?.into(),
            message: Box::into_raw(Box::new(match msg {
                BmpMessage::V3(value) => BmpMessageValueOpaque(value)
            })),
        });
    }

    let err = result.err().unwrap();

    let netgauze_error = CString::new(err.to_string()).unwrap();

    ParseError::NetgauzeError(netgauze_error.into_raw()).into()
}

#[repr(C)]
#[derive(Debug)]
pub struct CSlice {
    base_ptr: *mut c_void,
    stride: usize,
    end_ptr: *mut c_void,
    len: usize,
    cap: usize,
}

#[no_mangle]
pub extern "C" fn bmp_init_get_tlvs(bmp_init: *const BmpMessageValueOpaque) -> CSlice {
    let bmp_init = unsafe { &bmp_init.as_ref().unwrap().0 };

    let init = match bmp_init {
        BmpMessageValue::Initiation(init) => init,
        _ => unreachable!() // TODO make it an error
    };

    let mut tlvs = Vec::<bmp_log_tlv>::with_capacity(init.information().len());

    for tlv in init.information() {
        tlvs.push(bmp_log_tlv {
            pen: 0,
            type_: tlv.get_type().into(),
            len: (tlv.len() - InitiationInformation::BASE_LENGTH) as u16,
            val: tlv.get_value_ptr(),
        })
    }

    let (ptr, len, cap) = tlvs.into_raw_parts();

    let c_slice = CSlice {
        base_ptr: ptr as *mut c_void,
        stride: size_of::<bmp_log_tlv>(),
        end_ptr: unsafe { ptr.add(len) } as *mut c_void,
        len,
        cap,
    };

    println!("bmp_init_get_tlvs: {:#?}", &c_slice);

    c_slice
}

#[no_mangle]
pub extern "C" fn nonce9() {}
