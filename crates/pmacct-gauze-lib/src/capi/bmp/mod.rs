use crate::cresult::CResult;
use crate::extensions::bmp_message::ExtendBmpPeerHeader;
use crate::extensions::information_tlv::TlvExtension;
use crate::free_cslice_t;
use crate::slice::CSlice;
pub use crate::slice::RustFree;
use libc::{AF_INET, AF_INET6};
use netgauze_bmp_pkt::iana::BmpMessageType;
use netgauze_bmp_pkt::{BmpMessageValue, InitiationInformation, TerminationInformation};
use netgauze_parse_utils::WritablePdu;
use pmacct_gauze_bindings::{bmp_chars, bmp_data, bmp_log_tlv, host_addr, rd_t, timeval, u_int8_t};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::ptr;

pub mod parse;
pub mod peer_state;
pub mod print;
pub mod stats;

#[derive(Debug)]
pub struct BmpMessageValueOpaque(BmpMessageValue);

impl BmpMessageValueOpaque {
    pub fn value(&self) -> &BmpMessageValue {
        &self.0
    }
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
