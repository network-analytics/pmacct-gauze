use std::collections::HashMap;
use std::ffi::CString;
use libc;
use netgauze_bmp_pkt::{BmpMessage, BmpMessageValue, InitiationInformation};
use netgauze_parse_utils::{Span, WritablePdu};
use nom::Offset;
use pmacct_gauze_bindings::{bmp_common_hdr, bmp_peer_hdr, bmp_log_tlv};
use netgauze_parse_utils::ReadablePduWithOneInput;
use std::slice;
use crate::error::ParseError;
use crate::extensions::bmp_message::ExtendBmpMessage;
use crate::extensions::initiation_information::TlvExtension;
use crate::option::COption;
use crate::slice::CSlice;

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
pub struct ParseOk {
    read_bytes: u32,
    common_header: bmp_common_hdr,
    peer_header: COption<bmp_peer_hdr>,
    pub(crate) message: *mut BmpMessageValueOpaque,
}

#[repr(C)]
pub enum ParseResultEnum {
    ParseSuccess(ParseOk),
    ParseFailure(ParseError),
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


#[no_mangle]
pub extern "C" fn bmp_init_get_tlvs(bmp_init: *const BmpMessageValueOpaque) -> CSlice<bmp_log_tlv> {
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

    let c_slice = unsafe {
        CSlice::from_vec(tlvs)
    };

    // println!("bmp_init_get_tlvs: {:#?}", &c_slice);

    c_slice
}

// TODO macro to generate free functions for generics automatically
#[no_mangle]
pub extern "C" fn CSlice_free_bmp_log_tlv(slice: CSlice<bmp_log_tlv>) {
    unsafe {
        drop(Vec::from_raw_parts(slice.base_ptr, slice.len, slice.cap));
    }
}

#[no_mangle]
pub extern "C" fn nonce9() {}
