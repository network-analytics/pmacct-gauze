use std::cmp::max;
use std::os::raw::c_char;

use netgauze_bgp_pkt::capabilities::BgpCapability;
use netgauze_bgp_pkt::iana::AS_TRANS;
use netgauze_bgp_pkt::BgpMessage;
use netgauze_parse_utils::WritablePdu;

use pmacct_gauze_bindings::convert::TryConvertInto;
use pmacct_gauze_bindings::{as_t, bgp_peer, host_addr};

use crate::capi::bgp::WrongBgpMessageTypeError;
use crate::cresult::CResult;
use crate::extensions::add_path::AddPathCapabilityValue;
use crate::log::{pmacct_log, LogPriority};
use crate::opaque::Opaque;

#[repr(C)]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BgpOpenProcessError {
    WrongBgpMessageTypeError(WrongBgpMessageTypeError),
    BadPeerASN(as_t),
}

pub type BgpOpenProcessResult = CResult<usize, BgpOpenProcessError>;

#[allow(clippy::not_unsafe_ptr_arg_deref)] // The pointer is not null by contract
#[no_mangle]
pub extern "C" fn netgauze_bgp_process_open(
    bgp_msg: *const Opaque<BgpMessage>,
    bgp_peer: *mut bgp_peer,
) -> BgpOpenProcessResult {
    let bgp_msg = unsafe { bgp_msg.as_ref().unwrap().as_ref() };
    let peer = unsafe { bgp_peer.as_mut().unwrap() };

    let open = match bgp_msg {
        BgpMessage::Open(open) => open,
        _ => {
            return CResult::Err(BgpOpenProcessError::WrongBgpMessageTypeError(
                WrongBgpMessageTypeError(bgp_msg.get_type().into()),
            ))
        }
    };

    peer.status = pmacct_gauze_bindings::Active as u8;
    peer.ht = open.hold_time(); // FIXME pmacct has an upper bound of 5 for this. same?
    peer.id = host_addr::from(&open.bgp_id());
    peer.version = open.version(); // FIXME pmacct limits this to 4 only. same?

    // TODO Router id check

    peer.as_ = open.my_asn4(); // this is either the asn4 or the as,
    if peer.as_ == AS_TRANS as u32 || peer.as_ == 0 {
        return CResult::Err(BgpOpenProcessError::BadPeerASN(peer.as_));
    }

    let open_params = open.capabilities();
    for capability in open_params {
        match capability {
            BgpCapability::MultiProtocolExtensions(_) => {
                peer.cap_mp = u8::from(true);
            }
            BgpCapability::FourOctetAs(_) => {
                // TODO fix in pmacct: very ugly way to deal with this capability
                //  this will be fixed when bgp decoding is done by netgauze
                peer.cap_4as = u8::from(true) as *mut c_char;
            }
            BgpCapability::AddPath(addpath) => {
                for addpath_af in addpath.address_families() {
                    let address_type = addpath_af.address_type();
                    let send = addpath_af.send();
                    let recv = addpath_af.receive();

                    let (afi, safi) = if let Ok(afi_safi) = address_type.try_convert_to() {
                        afi_safi
                    } else {
                        pmacct_log(
                            LogPriority::Warning,
                            &format!(
                                "[pmacct-gauze] add-path AF {:?} not supported in pmacct!\n",
                                address_type
                            ),
                        );
                        continue;
                    };

                    peer.cap_add_paths.cap[afi as usize][safi as usize] = if send && recv {
                        AddPathCapabilityValue::Both
                    } else if send {
                        AddPathCapabilityValue::SendOnly
                    } else if recv {
                        AddPathCapabilityValue::ReceiveOnly
                    } else {
                        AddPathCapabilityValue::Unset
                    }
                        as u8;

                    peer.cap_add_paths.afi_max = max(afi, peer.cap_add_paths.afi_max);
                    peer.cap_add_paths.safi_max = max(safi, peer.cap_add_paths.safi_max);
                }
            }
            BgpCapability::RouteRefresh
            | BgpCapability::EnhancedRouteRefresh
            | BgpCapability::CiscoRouteRefresh
            | BgpCapability::GracefulRestartCapability(_)
            | BgpCapability::ExtendedMessage
            | BgpCapability::MultipleLabels(_)
            | BgpCapability::BgpRole(_)
            | BgpCapability::ExtendedNextHopEncoding(_)
            | BgpCapability::Unrecognized(_)
            | BgpCapability::Experimental(_) => {
                pmacct_log(
                    LogPriority::Warning,
                    &format!(
                        "[pmacct-gauze] warn! capability {:?} is not supported in pmacct\n",
                        capability
                    ),
                );
            }
        }
    }

    peer.status = pmacct_gauze_bindings::Established as u8;

    CResult::Ok(bgp_msg.len()) // use BgpMessage and not BgpOpenMessage for full length (marker, etc.)
}
