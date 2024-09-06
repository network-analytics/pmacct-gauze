use netgauze_bgp_pkt::BgpMessage;
use netgauze_bmp_pkt::{BmpMessageValue, PeerDownNotificationReason};
use netgauze_parse_utils::WritablePdu;

use pmacct_gauze_bindings::{bmp_log_peer_down, bmp_log_peer_up, host_addr, u_char};

use crate::capi::bmp::WrongBmpMessageTypeError;
use crate::cresult::CResult;
use crate::opaque::Opaque;

pub type BmpPeerUpHdrResult = CResult<bmp_log_peer_up, WrongBmpMessageTypeError>;

#[no_mangle]
pub extern "C" fn netgauze_bmp_peer_up_get_hdr(
    bmp_message_value_opaque: *const Opaque<BmpMessageValue>,
) -> BmpPeerUpHdrResult {
    let bmp_value = unsafe { bmp_message_value_opaque.as_ref().unwrap().as_ref() };

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

/// The `message` pointer is borrowed
#[repr(C)]
pub struct BmpPeerUpOpen {
    message: *const Opaque<BgpMessage>,
    message_size: usize,
}

pub type BmpPeerUpOpenResult = CResult<BmpPeerUpOpen, WrongBmpMessageTypeError>;

#[no_mangle]
pub extern "C" fn netgauze_bmp_peer_up_get_open_rx(
    bmp_message_value_opaque: *const Opaque<BmpMessageValue>,
) -> BmpPeerUpOpenResult {
    let bmp_value = unsafe { bmp_message_value_opaque.as_ref().unwrap().as_ref() };

    // Ensure passed value is a supported Bmp Message Type
    let peer_up = match bmp_value {
        BmpMessageValue::PeerUpNotification(peer_up) => peer_up,
        _ => return WrongBmpMessageTypeError(bmp_value.get_type().into()).into(),
    };

    let open = peer_up.received_message();
    CResult::Ok(BmpPeerUpOpen {
        message: open as *const BgpMessage as *const Opaque<BgpMessage>,
        message_size: open.len(),
    })
}

#[no_mangle]
pub extern "C" fn netgauze_bmp_peer_up_get_open_tx(
    bmp_message_value_opaque: *const Opaque<BmpMessageValue>,
) -> BmpPeerUpOpenResult {
    let bmp_value = unsafe { bmp_message_value_opaque.as_ref().unwrap().as_ref() };

    // Ensure passed value is a supported Bmp Message Type
    let peer_up = match bmp_value {
        BmpMessageValue::PeerUpNotification(peer_up) => peer_up,
        _ => return WrongBmpMessageTypeError(bmp_value.get_type().into()).into(),
    };

    let open = peer_up.sent_message();
    // TODO change this when NetGauze stores a BgpOpenMessage instead of a BgpMessage
    CResult::Ok(BmpPeerUpOpen {
        message: open as *const BgpMessage as *const Opaque<BgpMessage>,
        message_size: open.len(),
    })
}

pub type BmpPeerDownInfoResult = CResult<bmp_log_peer_down, WrongBmpMessageTypeError>;

#[no_mangle]
pub extern "C" fn netgauze_bmp_peer_down_get_info(
    bmp_message_value_opaque: *const Opaque<BmpMessageValue>,
) -> BmpPeerDownInfoResult {
    let bmp_value = unsafe { bmp_message_value_opaque.as_ref().unwrap().as_ref() };

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
