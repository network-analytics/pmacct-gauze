use netgauze_bgp_pkt::BgpMessage;

use crate::capi::bgp::WrongBgpMessageTypeError;
use crate::cresult::CResult;
use crate::extensions::bgp_notification::ExtendBgpNotificationMessage;
use crate::opaque::Opaque;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct BgpNotification {
    code: u8,
    subcode: u8,
    value_len: usize,
    value: *const u8,
}
pub type BgpNotificationResult = CResult<BgpNotification, WrongBgpMessageTypeError>;

#[no_mangle]
pub extern "C" fn netgauze_bgp_notification(
    bgp_message: *const Opaque<BgpMessage>,
) -> BgpNotificationResult {
    let bgp_message = unsafe { bgp_message.as_ref().unwrap().as_ref() };

    let bgp_notification = match bgp_message {
        BgpMessage::Notification(notif) => notif,
        _ => return WrongBgpMessageTypeError(bgp_message.get_type().into()).into(),
    };

    let code = bgp_notification.code() as u8;
    let subcode = bgp_notification.raw_subcode();
    let value = bgp_notification.value_ptr();

    CResult::Ok(BgpNotification {
        code,
        subcode,
        value_len: value.len(),
        value: value.as_ptr(),
    })
}
