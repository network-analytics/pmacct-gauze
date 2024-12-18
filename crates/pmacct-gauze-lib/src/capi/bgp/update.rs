use ipnet::Ipv4Net;
use netgauze_bgp_pkt::nlri::{MplsLabel, RouteDistinguisher};
use netgauze_bgp_pkt::path_attribute::{
    Aigp, As4Path, AsPath, MpReach, MpUnreach, PathAttribute, PathAttributeValue,
};
use netgauze_bgp_pkt::BgpMessage;
use netgauze_bmp_pkt::BmpMessageValue;
use netgauze_parse_utils::{WritablePdu, WritablePduWithOneInput};
use pmacct_gauze_bindings::convert::{TryConvertFrom, TryConvertInto};
use pmacct_gauze_bindings::{
    afi_t, aspath_parse, bgp_attr, bgp_attr_extra, bgp_peer, community_add_val, community_intern,
    community_new, ecommunity_add_val, ecommunity_intern, ecommunity_new, ecommunity_val,
    host_addr, in_addr, lcommunity_add_val, lcommunity_intern, lcommunity_new, lcommunity_val,
    path_id_t, prefix, rd_t, safi_t, DefaultZeroed, AFI_IP, BGP_BMAP_ATTR_AIGP,
    BGP_BMAP_ATTR_LOCAL_PREF, BGP_BMAP_ATTR_MULTI_EXIT_DISC, BGP_NLRI_EOR, BGP_NLRI_UPDATE,
    BGP_NLRI_WITHDRAW, SAFI_UNICAST,
};
use std::fmt::{Debug, Formatter};
use std::io::BufWriter;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use crate::capi::bgp::{reconcile_as24path, DebugUpdateType, WrongBgpMessageTypeError};
use crate::cresult::CResult;
use crate::cslice::OwnedSlice;
use crate::cslice::RustFree;
use crate::extensions::community::{ExtendExtendedCommunity, ExtendLargeCommunity};
use crate::extensions::rd::{ExtendRdT, RdOriginType};
use crate::free_cslice_t;
use crate::log::{pmacct_log, LogPriority};
use crate::opaque::Opaque;

free_cslice_t!(u8);

/// Serialize the BGP Update in a Route Monitoring Message
/// # Safety
/// `bmp_rm` should be not null and point to valid data
pub unsafe extern "C" fn netgauze_bgp_update_nlri_naive_copy(
    bmp_rm: *const Opaque<BmpMessageValue>,
) -> OwnedSlice<u8> {
    let bmp_rm = unsafe { bmp_rm.as_ref().unwrap() };

    let bmp_rm = match bmp_rm.as_ref() {
        BmpMessageValue::RouteMonitoring(rm) => rm,
        _ => unreachable!(),
    };

    let update = bmp_rm.update_message();

    let mut buf = Vec::with_capacity(bmp_rm.len());
    let written = {
        let mut writer = BufWriter::new(&mut buf);
        update.write(&mut writer)
    };

    if written.is_ok() {
        OwnedSlice::from_vec(buf)
    } else {
        OwnedSlice::dummy()
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct ParsedBgpUpdate {
    pub packets: OwnedSlice<ProcessPacket>,
    pub update_count: usize,
}

#[repr(C)]
pub struct ProcessPacket {
    update_type: u32,
    afi: afi_t,
    safi: safi_t,
    prefix: prefix,
    attr: bgp_attr,
    attr_extra: bgp_attr_extra,
}

free_cslice_t!(ProcessPacket);

impl Debug for ProcessPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("ProcessPacket");

        debug.field("update_type", &DebugUpdateType(self.update_type));
        debug.field("prefix", &self.prefix);
        debug.field("attr", &self.attr);
        debug.field("attr_extra", &self.attr_extra);
        debug.field("afi", &self.afi);
        debug.field("safi", &self.safi);

        debug.finish()
    }
}

pub fn process_mp_unreach(
    mp_unreach: &MpUnreach,
    attr: &mut bgp_attr,
    attr_extra: &mut bgp_attr_extra,
    packets: &mut Vec<ProcessPacket>,
) {
    let (afi, safi) = match (
        mp_unreach.afi().try_convert_to(),
        mp_unreach.safi().try_convert_to(),
    ) {
        (Ok(afi), Ok(safi)) => (afi, safi),
        _ => {
            pmacct_log(
                LogPriority::Warning,
                &format!(
                    "[pmacct-gauze] warn! could not convert MpUnreach afi/safi {}/{} to pmacct\n",
                    mp_unreach.afi(),
                    mp_unreach.safi()
                ),
            );
            return;
        }
    };

    let update_type = BGP_NLRI_WITHDRAW;

    match mp_unreach {
        // pmacct only has AFI IPv4/6 & BGP-LS
        // and SAFI UNICAST MPLS-LABEL MPLS-VPN
        MpUnreach::Ipv4Unicast { nlri: nlris } => {
            for nlri in nlris {
                fill_path_id(attr_extra, nlri.path_id());

                packets.push(ProcessPacket {
                    update_type,
                    prefix: prefix::from(&nlri.network().address()),
                    attr: *attr,
                    attr_extra: *attr_extra,
                    afi,
                    safi,
                });
            }
        }
        MpUnreach::Ipv4NlriMplsLabels { nlri: nlris } => {
            for nlri in nlris {
                fill_path_id(attr_extra, nlri.path_id());
                fill_mpls_label(attr_extra, nlri.labels());

                packets.push(ProcessPacket {
                    update_type,
                    prefix: prefix::from(&nlri.prefix()),
                    attr: *attr,
                    attr_extra: *attr_extra,
                    afi,
                    safi,
                });
            }
        }
        MpUnreach::Ipv4MplsVpnUnicast { nlri: nlris } => {
            for nlri in nlris {
                fill_path_id(attr_extra, nlri.path_id());
                fill_mpls_label(attr_extra, nlri.label_stack());
                fill_rd(attr_extra, nlri.rd());

                packets.push(ProcessPacket {
                    update_type,
                    prefix: prefix::from(&nlri.network().address()),
                    attr: *attr,
                    attr_extra: *attr_extra,
                    afi,
                    safi,
                })
            }
        }
        MpUnreach::Ipv6Unicast { nlri: nlris } => {
            for nlri in nlris {
                fill_path_id(attr_extra, nlri.path_id());

                packets.push(ProcessPacket {
                    update_type,
                    prefix: prefix::from(&nlri.network().address()),
                    attr: *attr,
                    attr_extra: *attr_extra,
                    afi,
                    safi,
                })
            }
        }
        MpUnreach::Ipv6NlriMplsLabels { nlri: nlris } => {
            for nlri in nlris {
                fill_path_id(attr_extra, nlri.path_id());
                fill_mpls_label(attr_extra, nlri.labels());

                packets.push(ProcessPacket {
                    update_type,
                    prefix: prefix::from(&nlri.prefix()),
                    attr: *attr,
                    attr_extra: *attr_extra,
                    afi,
                    safi,
                })
            }
        }
        MpUnreach::Ipv6MplsVpnUnicast { nlri: nlris } => {
            for nlri in nlris {
                fill_path_id(attr_extra, nlri.path_id());
                fill_mpls_label(attr_extra, nlri.label_stack());
                fill_rd(attr_extra, nlri.rd());

                packets.push(ProcessPacket {
                    update_type,
                    prefix: prefix::from(&nlri.network().address()),
                    attr: *attr,
                    attr_extra: *attr_extra,
                    afi,
                    safi,
                })
            }
        }

        // not supported by pmacct
        MpUnreach::Ipv4Multicast { .. }
        | MpUnreach::Ipv6Multicast { .. }
        | MpUnreach::L2Evpn { .. }
        | MpUnreach::RouteTargetMembership { .. }
        | MpUnreach::BgpLs { .. }
        | MpUnreach::BgpLsVpn { .. }
        | MpUnreach::Unknown { .. } => {
            pmacct_log(LogPriority::Warning, &format!("[pmacct-gauze] warn! received mp_unreach with unsupported or unknown afi/safi {}/{} address type {:?}\n",
                                                      mp_unreach.afi(), mp_unreach.safi(), mp_unreach.address_type()));
        }
    }
}
pub fn process_mp_reach(
    mp_reach: &MpReach,
    attr: &mut bgp_attr,
    attr_extra: &mut bgp_attr_extra,
    packets: &mut Vec<ProcessPacket>,
) {
    let (afi, safi) = match (
        mp_reach.afi().try_convert_to(),
        mp_reach.safi().try_convert_to(),
    ) {
        (Ok(afi), Ok(safi)) => (afi, safi),
        _ => {
            pmacct_log(
                LogPriority::Warning,
                &format!(
                    "[pmacct-gauze] warn! could not convert MpReach afi/safi {}/{} to pmacct\n",
                    mp_reach.afi(),
                    mp_reach.safi()
                ),
            );
            return;
        }
    };

    let update_type = BGP_NLRI_UPDATE;

    match mp_reach {
        // pmacct only has AFI IPv4/6 & BGP-LS
        // and SAFI UNICAST MPLS-LABEL MPLS-VPN
        MpReach::Ipv4Unicast {
            next_hop,
            next_hop_local: _,
            nlri: nlris,
        } => {
            fill_attr_mp_next_hop(attr, next_hop);

            for nlri in nlris {
                fill_path_id(attr_extra, nlri.path_id());

                packets.push(ProcessPacket {
                    update_type,
                    prefix: prefix::from(&nlri.network().address()),
                    attr: *attr,
                    attr_extra: *attr_extra,
                    afi,
                    safi,
                });
            }
        }
        MpReach::Ipv4NlriMplsLabels {
            next_hop,
            next_hop_local: _,
            nlri: nlris,
        } => {
            fill_attr_mp_next_hop(attr, next_hop);

            for nlri in nlris {
                fill_path_id(attr_extra, nlri.path_id());
                fill_mpls_label(attr_extra, nlri.labels());

                packets.push(ProcessPacket {
                    update_type,
                    prefix: prefix::from(&nlri.prefix()),
                    attr: *attr,
                    attr_extra: *attr_extra,
                    afi,
                    safi,
                });
            }
        }
        MpReach::Ipv4MplsVpnUnicast {
            next_hop,
            nlri: nlris,
        } => {
            fill_attr_mp_next_hop(attr, &next_hop.next_hop());

            for nlri in nlris {
                fill_path_id(attr_extra, nlri.path_id());
                fill_mpls_label(attr_extra, nlri.label_stack());
                fill_rd(attr_extra, nlri.rd());

                packets.push(ProcessPacket {
                    update_type,
                    prefix: prefix::from(&nlri.network().address()),
                    attr: *attr,
                    attr_extra: *attr_extra,
                    afi,
                    safi,
                })
            }
        }
        MpReach::Ipv6Unicast {
            next_hop_global,
            next_hop_local: _,
            nlri: nlris,
        } => {
            fill_attr_ipv6_next_hop(attr, next_hop_global);

            for nlri in nlris {
                fill_path_id(attr_extra, nlri.path_id());

                packets.push(ProcessPacket {
                    update_type,
                    prefix: prefix::from(&nlri.network().address()),
                    attr: *attr,
                    attr_extra: *attr_extra,
                    afi,
                    safi,
                });
            }
        }
        MpReach::Ipv6NlriMplsLabels {
            next_hop,
            next_hop_local: _next_hop_local,
            nlri: nlris,
        } => {
            fill_attr_mp_next_hop(attr, next_hop);

            for nlri in nlris {
                fill_path_id(attr_extra, nlri.path_id());
                fill_mpls_label(attr_extra, nlri.labels());

                packets.push(ProcessPacket {
                    update_type,
                    prefix: prefix::from(&nlri.prefix()),
                    attr: *attr,
                    attr_extra: *attr_extra,
                    afi,
                    safi,
                })
            }
        }
        MpReach::Ipv6MplsVpnUnicast {
            next_hop,
            nlri: nlris,
        } => {
            fill_attr_mp_next_hop(attr, &next_hop.next_hop());

            for nlri in nlris {
                fill_path_id(attr_extra, nlri.path_id());
                fill_mpls_label(attr_extra, nlri.label_stack());
                fill_rd(attr_extra, nlri.rd());

                packets.push(ProcessPacket {
                    update_type,
                    prefix: prefix::from(&nlri.network().address()),
                    attr: *attr,
                    attr_extra: *attr_extra,
                    afi,
                    safi,
                })
            }
        }

        // not supported by pmacct
        MpReach::Ipv4Multicast { .. }
        | MpReach::Ipv6Multicast { .. }
        | MpReach::L2Evpn { .. }
        | MpReach::RouteTargetMembership { .. }
        | MpReach::BgpLs { .. }
        | MpReach::BgpLsVpn { .. }
        | MpReach::Unknown { .. } => {
            pmacct_log(LogPriority::Warning, &format!("[pmacct-gauze] warn! received mp_reach with unsupported or unknown afi/safi {}/{} address type {:?}\n",
                                                      mp_reach.afi(), mp_reach.safi(), mp_reach.address_type()));
        }
    }
}

pub(crate) fn process_attributes(
    peer: *mut bgp_peer,
    attributes: &Vec<PathAttribute>,
) -> (
    Option<&MpReach>,
    Option<&MpUnreach>,
    bgp_attr,
    bgp_attr_extra,
) {
    let mut mp_reach = None;
    let mut mp_unreach = None;

    let mut attr: bgp_attr = unsafe { std::mem::zeroed() };
    let mut attr_extra: bgp_attr_extra = unsafe { std::mem::zeroed() };
    let mut as_path = ptr::null_mut();
    let mut as4_path = ptr::null_mut();

    // TODO free allocated C structs on error
    // TODO accept only one path attribute of each kind, error if multiple
    for _attr in attributes {
        match _attr.value() {
            PathAttributeValue::AsPath(aspath) => {
                let extended_length = _attr.extended_length();
                let mut bytes = Vec::with_capacity(aspath.len(extended_length));
                let bytes = {
                    let skip_length_offset = AsPath::BASE_LENGTH + usize::from(extended_length);
                    let mut writer = BufWriter::new(&mut bytes);
                    let _ = aspath.write(&mut writer, extended_length);
                    drop(writer);
                    bytes.split_at(skip_length_offset).1
                };

                as_path = unsafe {
                    // no need to intern as aspath_parse interns as well
                    aspath_parse(
                        peer,
                        bytes.as_ptr() as *mut i8,
                        bytes.len(),
                        i32::from(peer.read().cap_4as.used),
                    )
                };

                unsafe {
                    attr.aspath = reconcile_as24path(as_path, as4_path);
                }
            }
            PathAttributeValue::As4Path(as4path) => {
                let extended_length = _attr.extended_length();
                let mut bytes = Vec::with_capacity(as4path.len(extended_length));
                let bytes = {
                    let skip_length_offset = As4Path::BASE_LENGTH + usize::from(extended_length);
                    let mut writer = BufWriter::new(&mut bytes);
                    let _ = as4path.write(&mut writer, extended_length);
                    drop(writer);
                    bytes.split_at(skip_length_offset).1
                };

                as4_path = unsafe {
                    // no need to intern as aspath_parse interns as well
                    aspath_parse(
                        peer,
                        bytes.as_ptr() as *mut i8,
                        bytes.len(),
                        peer.read().cap_4as.used as i32,
                    )
                };

                attr.aspath = unsafe { reconcile_as24path(as_path, as4_path) };
            }
            PathAttributeValue::Communities(communities) => {
                // pmacct does not allow rehashing, let's just ignore if we have multiple com attributes
                if !attr.community.is_null() {
                    pmacct_log(LogPriority::Warning, "[pmacct-gauze] warn! multiple community attributes is not supported. ignored.\n");
                    continue;
                }

                let com = unsafe { community_new(peer) };

                for community in communities.communities() {
                    unsafe {
                        community_add_val(peer, com, community.value());
                    }
                }

                attr.community = unsafe { community_intern(peer, com) };
            }
            PathAttributeValue::LargeCommunities(large_communities) => {
                // pmacct does not allow rehashing, let's just ignore if we have multiple lcom attributes
                if !attr.lcommunity.is_null() {
                    pmacct_log(LogPriority::Warning, "[pmacct-gauze] warn! multiple lcommunity attributes is not supported. ignored.\n");
                    continue;
                }

                let lcom = unsafe { lcommunity_new(peer) };

                for lcommunity in large_communities.communities() {
                    let mut val = lcommunity.to_lcommunity_val();
                    unsafe {
                        lcommunity_add_val(peer, lcom, &mut val as *mut lcommunity_val);
                    }
                }

                attr.lcommunity = unsafe { lcommunity_intern(peer, lcom) };
            }
            PathAttributeValue::ExtendedCommunities(extended_communities) => {
                // pmacct does not allow rehashing, let's just ignore if we have multiple ecom attributes
                if !attr.ecommunity.is_null() {
                    pmacct_log(LogPriority::Warning, "[pmacct-gauze] warn! multiple ecommunity attributes is not supported. ignored.\n");
                    continue;
                }

                let ecom = unsafe { ecommunity_new(peer) };

                for ecommunity in extended_communities.communities() {
                    let mut val = ecommunity.to_ecommunity_val();
                    unsafe {
                        ecommunity_add_val(peer, ecom, &mut val as *mut ecommunity_val);
                    }
                }

                attr.ecommunity = unsafe { ecommunity_intern(peer, ecom) };
            }

            // straightforward primitives
            PathAttributeValue::Origin(origin) => attr.origin = (*origin).into(),
            PathAttributeValue::MultiExitDiscriminator(med) => {
                attr.med = med.metric();
                attr.bitmap |= BGP_BMAP_ATTR_MULTI_EXIT_DISC as u8;
            }
            PathAttributeValue::LocalPreference(local_pref) => {
                attr.local_pref = local_pref.metric();
                attr.bitmap |= BGP_BMAP_ATTR_LOCAL_PREF as u8;
            }

            PathAttributeValue::NextHop(next_hop) => {
                fill_attr_ipv4_next_hop(&mut attr, &next_hop.next_hop(), false)
            }

            PathAttributeValue::MpReach(mp_reach_attr) => {
                if mp_reach.replace(mp_reach_attr).is_some() {
                    pmacct_log(LogPriority::Warning, "[pmacct-gauze] warn! multiple mp_reach is not supported. ignoring previous mp_reach.\n")
                }
            }
            PathAttributeValue::MpUnreach(mp_unreach_attr) => {
                if mp_unreach.replace(mp_unreach_attr).is_some() {
                    pmacct_log(LogPriority::Warning, "[pmacct-gauze] warn! multiple mp_unreach is not supported. ignoring previous mp_unreach.\n")
                }
            }
            PathAttributeValue::OnlyToCustomer(otc) => attr_extra.otc = otc.asn(),
            PathAttributeValue::Aigp(Aigp::AccumulatedIgpMetric(aigp)) => {
                attr_extra.bitmap |= BGP_BMAP_ATTR_AIGP as u8;
                attr_extra.aigp = *aigp
            }
            PathAttributeValue::AtomicAggregate(_)
            | PathAttributeValue::ExtendedCommunitiesIpv6(_)
            | PathAttributeValue::Aggregator(_)
            | PathAttributeValue::Originator(_)
            | PathAttributeValue::ClusterList(_)
            | PathAttributeValue::BgpLs(_)
            | PathAttributeValue::PrefixSegmentIdentifier(_) => pmacct_log(
                LogPriority::Warning,
                &format!(
                    "[pmacct-gauze] warn! attribute type {} is not supported by pmacct\n",
                    _attr
                        .path_attribute_type()
                        .map(|__attr| __attr as u8)
                        .unwrap_or_else(|unknown| unknown)
                ),
            ),
            PathAttributeValue::UnknownAttribute(_) => pmacct_log(
                LogPriority::Warning,
                &format!(
                    "[pmacct-gauze] warn! attribute type {} is not supported by netgauze\n",
                    _attr
                        .path_attribute_type()
                        .map(|__attr| __attr as u8)
                        .unwrap_or_else(|unknown| unknown)
                ),
            ),
        };
    }

    (mp_reach, mp_unreach, attr, attr_extra)
}

pub type BgpUpdateResult = CResult<ParsedBgpUpdate, WrongBgpMessageTypeError>;

/// Get the updated NLRIs and their attributes from a [BgpMessage]
/// see [ProcessPacket]
///
/// # Safety
/// `peer` should be not null and point to valid data
/// `bgp_msg` should be not null and point to valid data
#[no_mangle]
pub unsafe extern "C" fn netgauze_bgp_update_get_updates(
    peer: *mut bgp_peer,
    bgp_msg: *const Opaque<BgpMessage>,
) -> BgpUpdateResult {
    let bgp_msg = unsafe { bgp_msg.as_ref().unwrap().as_ref() };

    let update = match bgp_msg {
        BgpMessage::Update(update) => update,
        _ => return WrongBgpMessageTypeError(bgp_msg.get_type().into()).into(),
    };

    let mut packets = Vec::with_capacity(update.withdraw_routes().len() + update.nlri().len());

    // Process Attributes
    let (mp_reach, mp_unreach, mut attr, mut attr_extra) =
        process_attributes(peer, update.path_attributes());

    // Handle Basic Updates
    for nlri in update.nlri() {
        packets.push(ProcessPacket {
            update_type: BGP_NLRI_UPDATE,
            prefix: prefix::from(&nlri.network().address()),
            attr,
            attr_extra,
            afi: AFI_IP as afi_t,
            safi: SAFI_UNICAST as safi_t,
        })
    }

    // Handle Basic Withdraws
    for withdraw in update.withdraw_routes() {
        packets.push(ProcessPacket {
            update_type: BGP_NLRI_WITHDRAW,
            prefix: prefix::from(&withdraw.network().address()),
            attr,
            attr_extra,
            afi: AFI_IP as afi_t,
            safi: SAFI_UNICAST as safi_t,
        })
    }

    if let Some(mp_reach) = mp_reach {
        process_mp_reach(mp_reach, &mut attr, &mut attr_extra, &mut packets);
    }

    // Always cleanup just in case
    cleanup_mp_reach(&mut attr, &mut attr_extra);

    if let Some(mp_unreach) = mp_unreach {
        process_mp_unreach(mp_unreach, &mut attr, &mut attr_extra, &mut packets);
    }

    // Handle EoR
    if let Some(address_type) = update.end_of_rib() {
        if let (Ok(afi), Ok(safi)) = (
            afi_t::try_convert_from(address_type.address_family()),
            safi_t::try_convert_from(address_type.subsequent_address_family()),
        ) {
            packets.push(ProcessPacket {
                update_type: BGP_NLRI_EOR,
                afi,
                safi,
                prefix: prefix::from(&Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 0).unwrap()), // This field should not be used
                attr,
                attr_extra,
            });
        } else {
            pmacct_log(
                LogPriority::Warning,
                &format!(
                    "[pmacct-gauze] warn! could not convert EoR afi/safi {}/{} to pmacct\n",
                    address_type.address_family(),
                    address_type.subsequent_address_family()
                ),
            );
        }
    }

    BgpUpdateResult::Ok(ParsedBgpUpdate {
        update_count: packets
            .iter()
            .filter(|x| x.update_type == BGP_NLRI_UPDATE)
            .count(),
        packets: OwnedSlice::from_vec(packets),
    })
}

fn fill_attr_ipv4_next_hop(attr: &mut bgp_attr, next_hop: &Ipv4Addr, mp_reach: bool) {
    if mp_reach {
        attr.mp_nexthop = host_addr::from(next_hop);
    } else {
        attr.nexthop = in_addr::from(next_hop);
    }
}

fn fill_attr_ipv6_next_hop(attr: &mut bgp_attr, next_hop: &Ipv6Addr) {
    attr.mp_nexthop = host_addr::from(next_hop)
}

fn fill_attr_mp_next_hop(attr: &mut bgp_attr, next_hop: &IpAddr) {
    match next_hop {
        IpAddr::V4(ipv4) => fill_attr_ipv4_next_hop(attr, ipv4, true),
        IpAddr::V6(ipv6) => fill_attr_ipv6_next_hop(attr, ipv6),
    };
}

fn fill_path_id(attr_extra: &mut bgp_attr_extra, path_id: Option<path_id_t>) {
    attr_extra.path_id = path_id.unwrap_or(0);
}

fn fill_mpls_label(attr_extra: &mut bgp_attr_extra, label_stack: &[MplsLabel]) {
    let bos = label_stack.iter().rev().find(|label| label.is_bottom());

    attr_extra.label = if let Some(bos) = bos {
        *bos.value()
    } else {
        [0, 0, 0]
    }
}

fn fill_rd(attr_extra: &mut bgp_attr_extra, rd: RouteDistinguisher) {
    attr_extra.rd = rd.into();
    attr_extra.rd.set_pmacct_rd_origin(RdOriginType::BGP);
}

/// Cleanup NLRI specific attributes
fn cleanup_mp_reach(attr: &mut bgp_attr, attr_extra: &mut bgp_attr_extra) {
    attr.nexthop = in_addr::default_zeroed();
    attr.mp_nexthop = host_addr::default_zeroed();

    attr_extra.path_id = 0;
    attr_extra.label = [0, 0, 0];
    attr_extra.rd = rd_t {
        type_: 0,
        as_: 0,
        val: 0,
    };
}
