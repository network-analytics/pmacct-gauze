use std::ffi::{c_char, CString};
use std::io::{BufWriter, Cursor};
use std::net::Ipv4Addr;
use std::slice;

use c_str_macro::c_str;
use netgauze_bgp_pkt::capabilities::{
    AddPathAddressFamily, AddPathCapability, BgpCapability, FourOctetAsCapability,
};
use netgauze_bgp_pkt::open::{BgpOpenMessage, BgpOpenMessageParameter};
use netgauze_bgp_pkt::BgpMessage;
use netgauze_parse_utils::WritablePdu;

use crate::capi::bgp::WrongBgpMessageTypeError;
use crate::cresult::CResult;
use crate::extensions::add_path::AddPathCapabilityValue;
use crate::log::{pmacct_log, LogPriority};
use crate::opaque::Opaque;
use pmacct_gauze_bindings::utils::cap_per_af::PerAddressTypeCapability;
use pmacct_gauze_bindings::{bgp_peer, cap_4as, cap_per_af, cap_per_af_u16, host_addr, in_addr, BGP_AS_TRANS};

#[repr(C)]
#[derive(Debug, Clone)]
pub enum BgpOpenProcessError {
    WrongBgpMessageType(WrongBgpMessageTypeError),
    BadBgpVersion(u8),
    FailedOpenRouterIdCheck(i32),
    BadBgpPeerState(u8),
    BadBgpPeerASN(u32),
}

pub type BgpOpenProcessResult = CResult<BgpOpenInfo, BgpOpenProcessError>;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct BgpOpenInfo {
    version: u8,
    asn: u16,
    hold_time: u16,
    bgp_id: host_addr,
    capability_mp_protocol: cap_per_af,
    capability_as4: cap_4as,
    capability_add_paths: cap_per_af,
    capability_route_refresh: bool,
    capability_ext_nh_enc_data: cap_per_af_u16,
}

/// Update the [bgp_peer] based on a [BgpMessage]
///
/// # Safety
/// `bgp_msg` should be not null and point to valid data
/// `bgp_peer` should be not null and point to valid data
#[no_mangle]
pub unsafe extern "C" fn netgauze_bgp_process_open(
    bgp_msg: *const Opaque<BgpMessage>
) -> BgpOpenProcessResult {
    let bgp_msg = unsafe { bgp_msg.as_ref().unwrap().as_ref() };

    let open = match bgp_msg {
        BgpMessage::Open(open) => open,
        _ => {
            return CResult::Err(BgpOpenProcessError::WrongBgpMessageType(
                WrongBgpMessageTypeError(bgp_msg.get_type().into()),
            ))
        }
    };

    let mut result = BgpOpenInfo {
        version: open.version(),
        asn: open.my_as(),
        hold_time: open.hold_time(),
        bgp_id: host_addr::from(&open.bgp_id()),
        capability_mp_protocol: std::mem::zeroed(),
        capability_as4: cap_4as { used: false, as4: 0 },
        capability_add_paths: std::mem::zeroed(),
        capability_route_refresh: false,
        capability_ext_nh_enc_data: std::mem::zeroed(),
    };

    // TODO pmacct duplicate router_id check needs to be done in pmacct still for live bgp

    let open_params = open.capabilities();
    for capability in open_params {
        match capability {
            BgpCapability::MultiProtocolExtensions(mp_ext) => {
                match result.capability_mp_protocol.set_value(mp_ext.address_type(), u8::from(true)) {
                    Ok(_) => {}
                    Err(err) => {
                        pmacct_log(
                            LogPriority::Warning,
                            &format!(
                                "[pmacct-gauze] Multi-Protocol Address Family {:?} is not supported in pmacct!\n",
                                err.0
                            ),
                        );
                    }
                }
            }
            BgpCapability::FourOctetAs(asn4) => {
                result.capability_as4 = cap_4as {
                    used: true,
                    as4: asn4.asn4(),
                };
            }
            BgpCapability::AddPath(addpath) => {
                let iter = addpath.address_families().iter().map(|add_path_address_family| {
                    (add_path_address_family.address_type(), AddPathCapabilityValue::from(add_path_address_family) as u8)
                });
                let (ok, errs) = cap_per_af::from_iter(iter);

                for err in errs {
                    pmacct_log(
                        LogPriority::Warning,
                        &format!(
                            "[pmacct-gauze] Add-Path Address Family {:?} is not supported in pmacct!\n",
                            err.0
                        ),
                    );
                }

                result.capability_add_paths = ok;
            }
            BgpCapability::RouteRefresh => {
                result.capability_route_refresh = true;
            }
            BgpCapability::ExtendedNextHopEncoding(extended_nexthop_encoding) => {
                let iter = extended_nexthop_encoding.encodings().iter().map(|encoding| {
                    (encoding.address_type(), encoding.next_hop_afi() as u16)
                });

                let (ok, errs) = cap_per_af_u16::from_iter(iter);

                for err in errs {
                    pmacct_log(
                        LogPriority::Warning,
                        &format!(
                            "[pmacct-gauze] Extended Next-Hop Encoding Address Family {:?} is not supported in pmacct!\n",
                            err.0
                        ),
                    );
                }
                result.capability_ext_nh_enc_data = ok;

            }
            BgpCapability::EnhancedRouteRefresh
            | BgpCapability::CiscoRouteRefresh
            | BgpCapability::GracefulRestartCapability(_)
            | BgpCapability::ExtendedMessage
            | BgpCapability::MultipleLabels(_)
            | BgpCapability::BgpRole(_)
            | BgpCapability::Unrecognized(_)
            | BgpCapability::Experimental(_) => {
                pmacct_log(
                    LogPriority::Warning,
                    &format!(
                        "[pmacct-gauze] warn! Capability {:?} is not supported in pmacct\n",
                        capability
                    ),
                );
            }
        }
    }

    CResult::Ok(result) // use BgpMessage and not BgpOpenMessage for full length (marker, etc.)
}

#[repr(C)]
#[derive(Debug, Clone)]
pub enum BgpOpenWriteError {
    WrongBgpMessageTypeError(WrongBgpMessageTypeError),
    MyAsnTooHighForRemotePeer,
    Asn4CapabilityFoundInOpenRxButNotInPeer,
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
        BgpOpenWriteError::Asn4CapabilityFoundInOpenRxButNotInPeer => c_str! {
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
    buf: *mut c_char,
    buf_len: usize,
    my_bgp_id: in_addr,
) -> BgpOpenWriteResult {
    let buf = unsafe { slice::from_raw_parts_mut(buf as *mut u8, buf_len) };
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
                                    BgpOpenWriteError::Asn4CapabilityFoundInOpenRxButNotInPeer,
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
