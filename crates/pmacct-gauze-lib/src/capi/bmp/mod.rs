use std::error::Error;
use std::fmt::{Display, Formatter};
use std::ptr;

use libc::{AF_INET, AF_INET6};
use netgauze_bgp_pkt::BgpMessage;
use netgauze_bmp_pkt::iana::BmpMessageType;
use netgauze_bmp_pkt::{BmpMessageValue, InitiationInformation, PeerKey, TerminationInformation};
use netgauze_parse_utils::WritablePdu;

use pmacct_gauze_bindings::{
    bmp_chars, bmp_data, bmp_log_tlv, host_addr, rd_t, timeval, u_int8_t, DefaultZeroed,
};

use crate::cresult::CResult;
use crate::cslice::OwnedSlice;
pub use crate::cslice::RustFree;
use crate::extensions::bmp_message::{ExtendBmpMessage, ExtendBmpPeerHeader};
use crate::extensions::information_tlv::TlvExtension;
use crate::extensions::rd::{ExtendRdT, RdOriginType};
use crate::free_cslice_t;
use crate::opaque::Opaque;

pub mod parse;
pub mod peer_state;
pub mod print;
pub mod stats;

impl Opaque<BmpMessageValue> {
    pub fn peer_key(&self) -> Option<PeerKey> {
        self.as_ref()
            .get_peer_header()
            .map(PeerKey::from_peer_header)
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

/// The `CSlice<bmp_log_tlv>` must be manually freed with [CSlice_free_bmp_log_tlv]
pub type BmpTlvListResult = CResult<OwnedSlice<bmp_log_tlv>, WrongBmpMessageTypeError>;

#[allow(clippy::not_unsafe_ptr_arg_deref)] // The pointer is not null by contract
#[no_mangle]
pub extern "C" fn netgauze_bmp_get_tlvs(
    bmp_message_value_opaque: *const Opaque<BmpMessageValue>,
) -> BmpTlvListResult {
    let bmp_value = unsafe { bmp_message_value_opaque.as_ref().unwrap().as_ref() };

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

    let c_slice = OwnedSlice::from_vec(tlvs);

    CResult::Ok(c_slice)
}

free_cslice_t!(bmp_log_tlv);

pub type BmpPeerHdrDataResult = CResult<bmp_data, WrongBmpMessageTypeError>;

#[allow(clippy::not_unsafe_ptr_arg_deref)] // The pointer is not null by contract
#[no_mangle]
pub extern "C" fn netgauze_bmp_peer_hdr_get_data(
    bmp_message_value_opaque: *const Opaque<BmpMessageValue>,
) -> BmpPeerHdrDataResult {
    let bmp_msg = unsafe { bmp_message_value_opaque.as_ref().unwrap().as_ref() };

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
            rib_type: peer_hdr.rib_type().map(u8::from).unwrap_or(0),
            rd: peer_hdr
                .rd()
                .map(|rd| {
                    let mut rd = rd_t::from(rd);
                    rd.set_pmacct_rd_origin(RdOriginType::BMP);
                    rd
                })
                .unwrap_or_else(rd_t::default_zeroed),
            tlvs: ptr::null_mut(), // TODO only used in bmp RM, make a Rust function like for init and fill field in C
        },
        tstamp: peer_hdr
            .timestamp()
            .map(timeval::from)
            .unwrap_or_else(timeval::default_zeroed),
        tstamp_arrival: timeval::now(),
    })
}

pub type BmpRouteMonitorUpdateResult = CResult<*const Opaque<BgpMessage>, WrongBmpMessageTypeError>;

#[no_mangle]
pub extern "C" fn netgauze_bmp_route_monitor_get_bgp_update(bmp_rm: *const Opaque<BmpMessageValue>) -> BmpRouteMonitorUpdateResult {
    let bmp_value = unsafe { bmp_rm.as_ref().unwrap().as_ref() };

    let bmp_rm = match bmp_value {
        BmpMessageValue::RouteMonitoring(rm) => rm,
        _ => return WrongBmpMessageTypeError(bmp_value.get_type().into()).into()
    };

    CResult::Ok(Opaque::const_from_ref(bmp_rm.update_message()))
}
