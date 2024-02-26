use crate::capi::bgp::BgpMessageOpaque;
use crate::extensions::bmp_message::{ExtendBmpMessage, ExtendBmpPeerHeader};
use crate::extensions::information_tlv::TlvExtension;
use crate::free_cslice_t;
use crate::log::{pmacct_log, LogPriority};
use crate::option::COption;
use crate::result::bmp_result::{BmpParseError, BmpParseResult, WrongBmpMessageTypeError};
use crate::result::cresult::CResult;
use crate::slice::CSlice;
use crate::slice::RustFree;
use libc::{AF_INET, AF_INET6};
use netgauze_bgp_pkt::BgpMessage;
use netgauze_bmp_pkt::{
    BmpMessage, BmpMessageValue, InitiationInformation, PeerDownNotificationReason,
    TerminationInformation,
};
use netgauze_parse_utils::{ReadablePduWithOneInput, Span, WritablePdu};
use nom::Offset;
use pmacct_gauze_bindings::{
    bmp_chars, bmp_common_hdr, bmp_data, bmp_log_peer_down, bmp_log_peer_up, bmp_log_stats,
    bmp_log_tlv, bmp_peer_hdr, host_addr, rd_t, timeval, u_char, u_int8_t,
};
use std::collections::HashMap;
use std::ffi::CString;
use std::{ptr, slice};

use crate::extensions::bmp_statistics::ExtendBmpStatistics;

#[derive(Debug)]
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

#[no_mangle]
pub extern "C" fn netgauze_bmp_print_message(
    bmp_message_value_opaque: *const BmpMessageValueOpaque,
) {
    let bmp_value = unsafe { bmp_message_value_opaque.as_ref().unwrap() };
    println!("{:#?}", bmp_value);
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
) -> BmpParseResult {
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

pub type BmpPeerHdrDataResult = CResult<bmp_data, WrongBmpMessageTypeError>;

#[no_mangle]
pub extern "C" fn netgauze_bmp_peer_hdr_get_data(
    bmp_message_value_opaque: *const BmpMessageValueOpaque,
) -> BmpPeerHdrDataResult {
    let bmp_msg = unsafe { bmp_message_value_opaque.as_ref().unwrap().value() };

    // Ensure passed value is a supported Bmp Message Type
    let peer_hdr = match bmp_msg {
        BmpMessageValue::RouteMonitoring(rm) => rm.peer_header(),
        BmpMessageValue::PeerUpNotification(peer_up) => peer_up.peer_header(),
        BmpMessageValue::StatisticsReport(stats) => stats.peer_header(),
        BmpMessageValue::PeerDownNotification(peer_down) => peer_down.peer_header(),
        _ => return WrongBmpMessageTypeError(bmp_msg.get_type().into()).into(),
    };

    CResult::Ok(bmp_data {
        family: if peer_hdr.is_v6().unwrap_or(false) {
            AF_INET6
        } else {
            AF_INET
        } as u_int8_t,
        peer_ip: peer_hdr
            .address()
            .as_ref()
            .map(host_addr::from)
            .unwrap_or_else(host_addr::default_ipv4),
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
        tstamp: peer_hdr
            .timestamp()
            .map(timeval::from)
            .unwrap_or_else(timeval::default),
        tstamp_arrival: timeval::now(),
    })
}

pub type BmpPeerUpHdrResult = CResult<bmp_log_peer_up, WrongBmpMessageTypeError>;

#[no_mangle]
pub extern "C" fn netgauze_bmp_peer_up_get_hdr(
    bmp_message_value_opaque: *const BmpMessageValueOpaque,
) -> BmpPeerUpHdrResult {
    let bmp_value = unsafe { bmp_message_value_opaque.as_ref().unwrap().value() };

    let peer_up = match bmp_value {
        BmpMessageValue::PeerUpNotification(peer_up) => peer_up,
        _ => return WrongBmpMessageTypeError(bmp_value.get_type().into()).into(),
    };

    CResult::Ok(bmp_log_peer_up {
        local_ip: peer_up
            .local_address()
            .as_ref()
            .map(host_addr::from)
            .unwrap_or_else(host_addr::default_ipv4),
        loc_port: peer_up.local_port().unwrap_or(0),
        rem_port: peer_up.remote_port().unwrap_or(0),
    })
}

#[repr(C)]
pub struct BmpPeerUpOpen {
    message: *const BgpMessageOpaque,
    message_size: usize,
}

pub type BmpPeerUpOpenResult = CResult<BmpPeerUpOpen, WrongBmpMessageTypeError>;

#[no_mangle]
pub extern "C" fn netgauze_bmp_peer_up_get_open_rx(
    bmp_message_value_opaque: *const BmpMessageValueOpaque,
) -> BmpPeerUpOpenResult {
    let bmp_value = unsafe { bmp_message_value_opaque.as_ref().unwrap().value() };

    // Ensure passed value is a supported Bmp Message Type
    let peer_up = match bmp_value {
        BmpMessageValue::PeerUpNotification(peer_up) => peer_up,
        _ => return WrongBmpMessageTypeError(bmp_value.get_type().into()).into(),
    };

    let open = peer_up.received_message();
    // TODO change this when NetGauze stores a BgpOpenMessage instead of a BgpMessage
    CResult::Ok(BmpPeerUpOpen {
        message: open as *const BgpMessage as *const BgpMessageOpaque,
        message_size: open.len(),
    })
}

#[no_mangle]
pub extern "C" fn netgauze_bmp_peer_up_get_open_tx(
    bmp_message_value_opaque: *const BmpMessageValueOpaque,
) -> BmpPeerUpOpenResult {
    let bmp_value = unsafe { bmp_message_value_opaque.as_ref().unwrap().value() };

    // Ensure passed value is a supported Bmp Message Type
    let peer_up = match bmp_value {
        BmpMessageValue::PeerUpNotification(peer_up) => peer_up,
        _ => return WrongBmpMessageTypeError(bmp_value.get_type().into()).into(),
    };

    let open = peer_up.sent_message();
    // TODO change this when NetGauze stores a BgpOpenMessage instead of a BgpMessage
    CResult::Ok(BmpPeerUpOpen {
        message: open as *const BgpMessage as *const BgpMessageOpaque,
        message_size: open.len(),
    })
}

pub type BmpTlvListResult = CResult<CSlice<bmp_log_tlv>, WrongBmpMessageTypeError>;

#[no_mangle]
pub extern "C" fn netgauze_bmp_get_tlvs(
    bmp_message_value_opaque: *const BmpMessageValueOpaque,
) -> BmpTlvListResult {
    let bmp_value = unsafe { bmp_message_value_opaque.as_ref().unwrap().value() };

    let tlvs = match bmp_value {
        BmpMessageValue::Initiation(init) => {
            let mut tlvs = Vec::<bmp_log_tlv>::with_capacity(init.information().len());

            for tlv in init.information() {
                tlvs.push(bmp_log_tlv {
                    pen: 0, // TODO support PEN when netgauze supports bmp v4
                    type_: tlv.get_type().into(),
                    len: (tlv.len() - InitiationInformation::BASE_LENGTH) as u16,
                    val: tlv.get_value_ptr(),
                })
            }

            tlvs
        }
        BmpMessageValue::PeerUpNotification(peer_up) => {
            let mut tlvs = Vec::<bmp_log_tlv>::with_capacity(peer_up.information().len());

            for tlv in peer_up.information() {
                tlvs.push(bmp_log_tlv {
                    pen: 0, // TODO support PEN when netgauze supports bmp v4
                    type_: tlv.get_type().into(),
                    len: (tlv.len() - InitiationInformation::BASE_LENGTH) as u16,
                    val: tlv.get_value_ptr(),
                })
            }

            tlvs
        }
        BmpMessageValue::Termination(term) => {
            let mut tlvs = Vec::<bmp_log_tlv>::with_capacity(term.information().len());

            for tlv in term.information() {
                tlvs.push(bmp_log_tlv {
                    pen: 0, // TODO support PEN when Netgauze supports bmp v4
                    type_: tlv.get_type().into(),
                    len: (tlv.len() - TerminationInformation::BASE_LENGTH) as u16,
                    val: tlv.get_value_ptr(),
                })
            }

            tlvs
        }
        _ => return WrongBmpMessageTypeError(bmp_value.get_type().into()).into(),
    };

    let c_slice = unsafe { CSlice::from_vec(tlvs) };

    CResult::Ok(c_slice)
}

free_cslice_t!(bmp_log_tlv);

pub type BmpStatsResult = CResult<CSlice<bmp_log_stats>, WrongBmpMessageTypeError>;

free_cslice_t!(bmp_log_stats);

#[no_mangle]
pub extern "C" fn netgauze_bmp_stats_get_stats(
    bmp_message_value_opaque: *const BmpMessageValueOpaque,
) -> BmpStatsResult {
    let bmp_value = unsafe { bmp_message_value_opaque.as_ref().unwrap().value() };

    // Ensure passed value is a supported Bmp Message Type
    let stats = match bmp_value {
        BmpMessageValue::StatisticsReport(stats) => stats,
        _ => return WrongBmpMessageTypeError(bmp_value.get_type().into()).into(),
    };

    let mut result = Vec::with_capacity(stats.counters().len());

    for stat in stats.counters() {
        let cnt_type = match stat.get_type() {
            Ok(type_) => type_ as u16,
            Err(code) => {
                pmacct_log(
                    LogPriority::Warning,
                    &format!(
                        "[pmacct-gauze] warn! stat type {code} is not supported by NetGauze\n"
                    ),
                );
                continue;
            }
        };

        let (cnt_afi, cnt_safi) = match stat.get_afi_safi() {
            Ok(None) => (0, 0),
            Ok(Some(afi_safi)) => afi_safi,
            Err(address_type) => {
                pmacct_log(
                    LogPriority::Warning,
                    &format!(
                        "[pmacct-gauze] warn! address type {:?}(afi={}, safi={}) is not supported by NetGauze\n",
                        address_type,
                        address_type.address_family(),
                        address_type.subsequent_address_family()
                    ),
                );
                continue;
            }
        };

        // This error will only happen for experimental values since Unknown has already been filtered out in cnt_type
        let cnt_data = match stat.get_value_as_u64() {
            Ok(value) => value,
            Err(()) => {
                pmacct_log(
                    LogPriority::Warning,
                    &format!(
                        "[pmacct-gauze] warn! stat type {} is not supported by NetGauze\n",
                        cnt_type
                    ),
                );
                continue;
            }
        };

        result.push(bmp_log_stats {
            cnt_type,
            cnt_afi,
            cnt_safi,
            cnt_data,
        });
    }

    let slice = unsafe { CSlice::from_vec(result) };
    CResult::Ok(slice)
}

pub type BmpPeerDownInfoResult = CResult<bmp_log_peer_down, WrongBmpMessageTypeError>;

#[no_mangle]
pub extern "C" fn netgauze_bmp_peer_down_get_info(
    bmp_message_value_opaque: *const BmpMessageValueOpaque,
) -> BmpPeerDownInfoResult {
    let bmp_value = unsafe { bmp_message_value_opaque.as_ref().unwrap().value() };

    let peer_down = match bmp_value {
        BmpMessageValue::PeerDownNotification(peer_down) => peer_down,
        _ => return WrongBmpMessageTypeError(bmp_value.get_type().into()).into(),
    };

    let loc_code = match peer_down.reason() {
        PeerDownNotificationReason::LocalSystemClosedFsmEventFollows(code) => *code,
        _ => 0,
    };

    CResult::Ok(bmp_log_peer_down {
        reason: peer_down.reason().get_type() as u_char,
        loc_code,
    })
}
