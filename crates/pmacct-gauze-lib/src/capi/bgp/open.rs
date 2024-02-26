use crate::capi::bgp::{BgpMessageOpaque, WrongBgpMessageTypeError};
use crate::cresult::CResult;
use crate::log::{pmacct_log, LogPriority};
use netgauze_bgp_pkt::capabilities::BgpCapability;
use netgauze_bgp_pkt::BgpMessage;
use netgauze_parse_utils::WritablePdu;
use pmacct_gauze_bindings::{bgp_peer, host_addr};
use std::cmp::max;
use std::os::raw::c_char;

pub type BgpOpenProcessResult = CResult<usize, WrongBgpMessageTypeError>;

#[no_mangle]
pub extern "C" fn netgauze_bgp_process_open(
    bgp_msg: *const BgpMessageOpaque,
    bgp_peer: *mut bgp_peer,
) -> BgpOpenProcessResult {
    let bgp_msg = unsafe { &bgp_msg.as_ref().unwrap().0 };
    let peer = unsafe { bgp_peer.as_mut().unwrap() };

    let open = match bgp_msg {
        BgpMessage::Open(open) => open,
        _ => return WrongBgpMessageTypeError(bgp_msg.get_type().into()).into(),
    };

    peer.status = pmacct_gauze_bindings::Active as u8;
    peer.ht = open.hold_time(); // FIXME pmacct has an upper bound of 5 for this. same?
    peer.id = host_addr::from(&open.bgp_id());
    peer.version = open.version(); // FIXME pmacct limits this to 4 only. same?

    // TODO pmacct duplicate router_id check needs to be done in pmacct still for live bgp

    peer.as_ = open.my_asn4(); // this is either the asn4 or the as, TODO error if as_ == AS_TRANS or == 0

    let open_params = open.capabilities();
    for capability in open_params {
        match capability {
            BgpCapability::MultiProtocolExtensions(_) => {
                peer.cap_mp = u8::from(true);
            }
            BgpCapability::FourOctetAs(_) => {
                peer.cap_4as = u8::from(true) as *mut c_char; // TODO pmacct: very ugly way to deal with this capability
            }
            BgpCapability::AddPath(addpath) => {
                for addpath_af in addpath.address_families() {
                    let address_family = addpath_af.address_type();
                    let send = addpath_af.send();
                    let recv = addpath_af.receive();

                    let afi = address_family.address_family();
                    let safi = address_family.subsequent_address_family();

                    // TODO check afi < AFI_MAX and safi < SAFI_MAX error if not the case
                    peer.cap_add_paths.cap[afi as usize][safi as usize] = if send && recv {
                        3
                    } else if send {
                        2
                    } else if recv {
                        1
                    } else {
                        unreachable!() // TODO error
                    };

                    peer.cap_add_paths.afi_max = max(afi.into(), peer.cap_add_paths.afi_max);
                    peer.cap_add_paths.safi_max = max(safi.into(), peer.cap_add_paths.safi_max);
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
