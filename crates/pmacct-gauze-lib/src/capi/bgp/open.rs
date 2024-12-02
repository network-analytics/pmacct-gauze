use std::cmp::max;
use std::ffi::{c_char, CString};
use std::io::{BufWriter, Cursor};
use std::net::Ipv4Addr;
use std::slice;

use c_str_macro::c_str;
use netgauze_bgp_pkt::capabilities::{
    AddPathAddressFamily, AddPathCapability, BgpCapability, FourOctetAsCapability,
};
use netgauze_bgp_pkt::iana::AS_TRANS;
use netgauze_bgp_pkt::open::{BgpOpenMessage, BgpOpenMessageParameter, BGP_VERSION};
use netgauze_bgp_pkt::BgpMessage;
use netgauze_parse_utils::WritablePdu;

use pmacct_gauze_bindings::convert::TryConvertInto;
use pmacct_gauze_bindings::{bgp_peer, cap_4as, host_addr, in_addr, BGP_AS_TRANS};

use crate::capi::bgp::open::BgpOpenProcessError::{BadBgpPeerASN, BadBgpPeerState};
use crate::capi::bgp::WrongBgpMessageTypeError;
use crate::cresult::CResult;
use crate::extensions::add_path::AddPathCapabilityValue;
use crate::log::{pmacct_log, LogPriority};
use crate::opaque::Opaque;

#[repr(C)]
#[derive(Debug, Clone)]
pub enum BgpOpenProcessError {
    WrongBgpMessageType(WrongBgpMessageTypeError),
    BadBgpVersion(u8),
    FailedOpenRouterIdCheck(i32),
    BadBgpPeerState(u8),
    BadBgpPeerASN(u32),
}

pub type BgpOpenProcessResult = CResult<usize, BgpOpenProcessError>;

/// Update the [bgp_peer] based on a [BgpMessage]
///
/// # Safety
/// `bgp_msg` should be not null and point to valid data
/// `bgp_peer` should be not null and point to valid data
#[no_mangle]
pub unsafe extern "C" fn netgauze_bgp_process_open(
    bgp_msg: *const Opaque<BgpMessage>,
    bgp_peer: *mut bgp_peer,
    max_hold_time: u16,
    // This flag seems to be always TRUE
    online: bool,
) -> BgpOpenProcessResult {
    let bgp_msg = unsafe { bgp_msg.as_ref().unwrap().as_ref() };
    let peer = unsafe { bgp_peer.as_mut().unwrap() };

    let open = match bgp_msg {
        BgpMessage::Open(open) => open,
        _ => {
            return CResult::Err(BgpOpenProcessError::WrongBgpMessageType(
                WrongBgpMessageTypeError(bgp_msg.get_type().into()),
            ))
        }
    };

    if open.version() != BGP_VERSION {
        return CResult::Err(BgpOpenProcessError::BadBgpVersion(open.version()));
    }

    if !online || peer.status as u32 >= pmacct_gauze_bindings::OpenSent {
        return CResult::Err(BadBgpPeerState(peer.status));
    }

    if open.my_asn4() == AS_TRANS as u32 || open.my_asn4() == 0 {
        return CResult::Err(BadBgpPeerASN(open.my_asn4()));
    }

    peer.version = open.version();
    peer.status = pmacct_gauze_bindings::Active as u8;
    peer.ht = max(open.hold_time(), max_hold_time);
    peer.id = host_addr::from(&open.bgp_id());

    // TODO pmacct duplicate router_id check needs to be done in pmacct still for live bgp

    peer.as_ = open.my_asn4(); // this is either the asn4 or the as,
    if peer.as_ == AS_TRANS as u32 || peer.as_ == 0 {
        return CResult::Err(BadBgpPeerASN(peer.as_));
    }

    let open_params = open.capabilities();
    for capability in open_params {
        match capability {
            BgpCapability::MultiProtocolExtensions(_) => {
                peer.cap_mp = u8::from(true);
            }
            BgpCapability::FourOctetAs(asn4) => {
                peer.cap_4as = cap_4as {
                    used: true,
                    as4: asn4.asn4(),
                };
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
            BgpCapability::RouteRefresh // BGP_CAPABILITY_ROUTE_REFRESH
            | BgpCapability::EnhancedRouteRefresh
            | BgpCapability::CiscoRouteRefresh
            | BgpCapability::GracefulRestartCapability(_)
            | BgpCapability::ExtendedMessage
            | BgpCapability::MultipleLabels(_)
            | BgpCapability::BgpRole(_)
            | BgpCapability::ExtendedNextHopEncoding(_) // TODO
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

#[repr(C)]
#[derive(Debug, Clone)]
pub enum BgpOpenWriteError {
    WrongBgpMessageTypeError(WrongBgpMessageTypeError),
    MyAsnTooHighForRemotePeer,
    PeerStateDoesNotMatchOpenRxMessage,
    NetgauzeWriteError { err_str: *mut c_char },
}

#[no_mangle]
pub extern "C" fn netgauze_bgp_open_write_result_err_str(
    value: BgpOpenWriteError,
) -> *const c_char {
    match value {
        BgpOpenWriteError::WrongBgpMessageTypeError(_) => c_str! {
            "BgpOpenWriteError::WrongBgpMessageTypeError"
        }
        .as_ptr(),
        BgpOpenWriteError::MyAsnTooHighForRemotePeer => c_str! {
            "BgpOpenWriteError::MyAsnTooHighForRemotePeer"
        }
        .as_ptr(),
        BgpOpenWriteError::PeerStateDoesNotMatchOpenRxMessage => c_str! {
            "BgpOpenWriteError::PeerStateDoesNotMatchOpenRxMessage"
        }
        .as_ptr(),
        BgpOpenWriteError::NetgauzeWriteError { err_str } => err_str,
    }
}

#[allow(clippy::single_match)]
#[no_mangle]
pub extern "C" fn netgauze_bgp_open_write_result_free(value: BgpOpenWriteResult) {
    match value {
        CResult::Ok(_) => {}
        CResult::Err(write_error) => match write_error {
            BgpOpenWriteError::NetgauzeWriteError { err_str, .. } => unsafe {
                drop(CString::from_raw(err_str));
            },
            _ => {}
        },
    };
}

pub type BgpOpenWriteResult = CResult<usize, BgpOpenWriteError>;

/// Process a received BGP Open and write a reply BGP Open with the correct capabilities for a collector
///
/// # Safety
/// `bgp_peer` should be not null and point to valid data
/// `open_rx` should be not null and point to valid data
/// `buf` should be not null and point a byte buffer we can write to
///
/// This function does not consume the `buf` pointer
#[no_mangle]
pub unsafe extern "C" fn netgauze_bgp_open_write_reply(
    bgp_peer: *const bgp_peer,
    open_rx: *const Opaque<BgpMessage>,
    buf: *mut u8,
    buf_len: usize,
    my_bgp_id: in_addr,
) -> BgpOpenWriteResult {
    let buf = unsafe { slice::from_raw_parts_mut(buf, buf_len) };
    let bgp_peer = unsafe { bgp_peer.as_ref().unwrap() };
    let bgp_msg = unsafe { open_rx.as_ref().unwrap().as_ref() };
    let open_rx = match bgp_msg {
        BgpMessage::Open(open_rx) => open_rx,
        _ => {
            return CResult::Err(BgpOpenWriteError::WrongBgpMessageTypeError(
                WrongBgpMessageTypeError(bgp_msg.get_type().into()),
            ))
        }
    };

    // Find the ASN and the AS4 if we have one
    let (my_as, as4_cap) = if bgp_peer.myas > u16::MAX as u32 {
        if !bgp_peer.cap_4as.used {
            return CResult::Err(BgpOpenWriteError::MyAsnTooHighForRemotePeer);
        }
        (BGP_AS_TRANS as u16, Some(open_rx.my_asn4()))
    } else {
        (
            bgp_peer.myas as u16,
            if bgp_peer.cap_4as.used {
                Some(open_rx.my_asn4())
            } else {
                None
            },
        )
    };

    // Modify received params to match our collector behaviour
    let mut tx_params: Vec<BgpOpenMessageParameter> = open_rx.params().clone();
    for param in &mut tx_params {
        match param {
            BgpOpenMessageParameter::Capabilities(ref mut caps) => {
                for cap in caps {
                    match cap {
                        // Ensure all add-path capabilities we send are receive-only
                        BgpCapability::AddPath(ref mut addpath) => {
                            let addpath_caps = addpath
                                .address_families()
                                .iter()
                                .map(|address_family| {
                                    AddPathAddressFamily::new(
                                        address_family.address_type(),
                                        false,
                                        true,
                                    )
                                })
                                .collect();
                            *addpath = AddPathCapability::new(addpath_caps);
                        }
                        BgpCapability::FourOctetAs(_) => {
                            // If we just found an ASN4 capability in the RX OPEN then we must have had an as4_cap in the peer state
                            if let Some(as4_value) = as4_cap {
                                *cap = BgpCapability::FourOctetAs(FourOctetAsCapability::new(
                                    as4_value,
                                ))
                            } else {
                                return CResult::Err(
                                    BgpOpenWriteError::PeerStateDoesNotMatchOpenRxMessage,
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // Write to buffer
    let bgp_open = BgpMessage::Open(BgpOpenMessage::new(
        my_as,
        bgp_peer.ht,
        Ipv4Addr::from(&my_bgp_id),
        tx_params,
    ));
    let mut cursor = Cursor::new(buf);
    let write_result = {
        let mut writer = BufWriter::new(&mut cursor);
        bgp_open.write(&mut writer)
    };

    match write_result {
        Ok(_) => CResult::Ok(cursor.position() as usize),
        Err(err) => CResult::Err(BgpOpenWriteError::NetgauzeWriteError {
            err_str: CString::new(format!("{:?}", err)).unwrap().into_raw(),
        }),
    }
}
