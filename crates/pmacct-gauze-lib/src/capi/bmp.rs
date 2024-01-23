use crate::extensions::bmp_message::{ExtendBmpMessage, ExtendBmpPeerHeader};
use crate::extensions::initiation_information::TlvExtension;
use crate::free_cslice_t;
use crate::option::COption;
use crate::result::bmp_result::{BmpParseError, BmpResult};
use crate::result::cresult::CResult;
use crate::slice::CSlice;
use netgauze_bmp_pkt::{BmpMessage, BmpMessageValue, InitiationInformation};
use netgauze_parse_utils::{ReadablePduWithOneInput, Span, WritablePdu};
use nom::Offset;
use pmacct_gauze_bindings::{bmp_chars, bmp_common_hdr, bmp_data, bmp_log_tlv, bmp_peer_hdr, host_addr, rd_t, timeval, u_int8_t};
use std::collections::HashMap;
use std::ffi::CString;
use std::{ptr, slice};
use libc::{AF_INET, AF_INET6};

pub struct BmpMessageValueOpaque(BmpMessageValue);

impl BmpMessageValueOpaque {
    pub fn value(&self) -> &BmpMessageValue {
        &self.0
    }
}

#[no_mangle]
pub extern "C" fn netgauze_bmp_print_packet(buffer: *const libc::c_char, len: u32) -> u32 {
    let s = unsafe { slice::from_raw_parts(buffer as *const u8, len as usize) };
    let span = Span::new(s);
    if let Ok((end_span, msg)) = BmpMessage::from_wire(span, &mut HashMap::new()) {
        println!("span: ptr: {:?} | value {:?}", span.as_ptr(), span);
        println!("msg: {:?}", msg);
        return span.offset(&end_span) as u32;
    }

    0
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
pub extern "C" fn netgauze_bmp_parse_packet(
    buffer: *const libc::c_char,
    buf_len: u32,
) -> BmpResult {
    let s = unsafe { slice::from_raw_parts(buffer as *const u8, buf_len as usize) };
    let span = Span::new(s);
    let result = BmpMessage::from_wire(span, &mut HashMap::new());
    if let Ok((end_span, msg)) = result {
        let read_bytes = span.offset(&end_span) as u32;

        return BmpResult::Ok(ParsedBmp {
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

    let netgauze_error = CString::new(err.to_string()).unwrap();

    BmpParseError::Netgauze(netgauze_error.into_raw()).into()
}

pub type BmpPeerHdrDataResult = CResult<bmp_data, BmpParseError>;

#[no_mangle]
pub extern "C" fn netgauze_bmp_peer_hdr_get_data(
    bmp_message_value_opaque: *const BmpMessageValueOpaque,
) -> BmpPeerHdrDataResult {
    let bmp_value = unsafe { &bmp_message_value_opaque.as_ref().unwrap().0 };

    // Ensure passed value is a supported Bmp Message Type
    let peer_hdr = match bmp_value {
        BmpMessageValue::RouteMonitoring(rm) => rm.peer_header(),
        BmpMessageValue::PeerUpNotification(peer_up) => peer_up.peer_header(),
        _ => return BmpParseError::WrongBmpMessageType.into(),
    };

    CResult::Ok(bmp_data {
        family: if peer_hdr.is_v6().unwrap_or(false) { AF_INET } else { AF_INET6 } as u_int8_t,
        peer_ip: peer_hdr.address().as_ref().map(host_addr::from).unwrap_or_else(host_addr::default),
        bgp_id: host_addr::from(&peer_hdr.bgp_id()),
        peer_asn: peer_hdr.peer_as(),
        chars: bmp_chars {
            peer_type: peer_hdr.peer_type().get_type() as u_int8_t,
            is_post: u_int8_t::from(peer_hdr.is_post().unwrap_or(false)),
            is_2b_asn: u_int8_t::from(!peer_hdr.is_asn4()),
            is_filtered: u_int8_t::from(peer_hdr.is_filtered().unwrap_or(false)),
            is_out: u_int8_t::from(peer_hdr.is_out().unwrap_or(false)),
            is_loc: u_int8_t::from(peer_hdr.is_loc()),
            rd: peer_hdr.rd().map(rd_t::from).unwrap_or_else(rd_t::default),
            tlvs: ptr::null_mut(), // TODO only used in bmp RM, make a Rust function like for init and fill field in C
        },
        tstamp: peer_hdr.timestamp().map(timeval::from).unwrap_or_else(timeval::default),
        tstamp_arrival: timeval::now(),
    })
}

pub type BmpInitTlvResult = CResult<CSlice<bmp_log_tlv>, BmpParseError>;

#[no_mangle]
pub extern "C" fn netgauze_bmp_init_get_tlvs(
    bmp_init: *const BmpMessageValueOpaque,
) -> BmpInitTlvResult {
    let bmp_init = unsafe { &bmp_init.as_ref().unwrap().0 };

    let init = match bmp_init {
        BmpMessageValue::Initiation(init) => init,
        _ => return BmpParseError::WrongBmpMessageType.into(),
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

    let c_slice = unsafe { CSlice::from_vec(tlvs) };

    // println!("bmp_init_get_tlvs: {:#?}", &c_slice);

    CResult::Ok(c_slice)
}

free_cslice_t!(bmp_log_tlv);
