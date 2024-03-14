use std::fmt::{Debug, Formatter};
use std::io::BufWriter;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;

use ipnet::Ipv4Net;
use netgauze_bgp_pkt::BgpMessage;
use netgauze_bgp_pkt::nlri::{MplsLabel, RouteDistinguisher};
use netgauze_bgp_pkt::path_attribute::{
    Aigp, As4Path, AsPath, MpReach, MpUnreach, PathAttributeValue,
};
use netgauze_bmp_pkt::BmpMessageValue;
use netgauze_parse_utils::{WritablePdu, WritablePduWithOneInput};

use pmacct_gauze_bindings::{AFI_IP, afi_t, aspath, aspath_parse, bgp_attr, bgp_attr_extra, BGP_BMAP_ATTR_AIGP, BGP_BMAP_ATTR_LOCAL_PREF, BGP_BMAP_ATTR_MULTI_EXIT_DISC, BGP_NLRI_UPDATE, BGP_NLRI_WITHDRAW, BGP_ORIGIN_UNKNOWN, bgp_peer, community, community_add_val, community_intern, community_new, ecommunity, ecommunity_add_val, ecommunity_intern, ecommunity_new, ecommunity_val, host_addr, in_addr, lcommunity, lcommunity_add_val, lcommunity_intern, lcommunity_new, lcommunity_val, path_id_t, prefix, rd_as, rd_t, safi_t, SAFI_UNICAST};

use crate::capi::bgp::{DebugUpdateType, reconcile_as24path, WrongBgpMessageTypeError};
use crate::capi::bmp::{BmpMessageValueOpaque, WrongBmpMessageTypeError};
use crate::cresult::CResult;
use crate::cslice::CSlice;
use crate::cslice::RustFree;
use crate::extensions::bgp_attribute::ExtendBgpAttribute;
use crate::extensions::community::{ExtendExtendedCommunity, ExtendLargeCommunity};
use crate::extensions::mp_reach::ExtendMpReach;
use crate::extensions::next_hop::ExtendLabeledNextHop;
use crate::extensions::rd::{ExtendRdT, RdOriginType};
use crate::free_cslice_t;
use crate::log::{LogPriority, pmacct_log};

free_cslice_t!(u8);

#[no_mangle]
pub extern "C" fn netgauze_bgp_update_nlri_naive_copy(
    bmp_rm: *const BmpMessageValueOpaque,
) -> CSlice<u8> {
    let bmp_rm = unsafe { bmp_rm.as_ref().unwrap() };

    let bmp_rm = match &bmp_rm.value() {
        BmpMessageValue::RouteMonitoring(rm) => rm,
        _ => unreachable!(),
    };

    let update = bmp_rm.update_message();

    let mut buf = Vec::with_capacity(bmp_rm.len());
    let written = {
        let mut writer = BufWriter::new(&mut buf);
        update.write(&mut writer)
    };

    let buf = if let Ok(_) = written {
        unsafe { CSlice::from_vec(buf) }
    } else {
        CSlice {
            base_ptr: ptr::null_mut(),
            stride: 0,
            end_ptr: ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    };

    buf
}

#[repr(C)]
#[derive(Debug)]
pub struct ParsedBgpUpdate {
    pub packets: CSlice<ProcessPacket>,
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

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct BgpParsedAttributes {
    aspath: *mut aspath,
    community: *mut community,
    ecommunity: *mut ecommunity,
    lcommunity: *mut lcommunity,
}

impl Default for BgpParsedAttributes {
    fn default() -> Self {
        Self {
            aspath: ptr::null_mut(),
            community: ptr::null_mut(),
            ecommunity: ptr::null_mut(),
            lcommunity: ptr::null_mut(),
        }
    }
}

pub type BgpUpdateResult = CResult<ParsedBgpUpdate, BgpUpdateError>;

// TODO use netgauze Variant(#[from] OtherError) macros
#[repr(C)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum BgpUpdateError {
    WrongBmpMessageType(WrongBmpMessageTypeError),
    WrongBgpMessageType(WrongBgpMessageTypeError),
}

impl<T> From<BgpUpdateError> for CResult<T, BgpUpdateError> {
    fn from(value: BgpUpdateError) -> Self {
        Self::Err(value)
    }
}

// TODO allocate separate community structs to avoid use after free bc pmacct decides to free the given communities with skip_rib
#[no_mangle]
pub extern "C" fn netgauze_bgp_update_get_updates(
    peer: *mut bgp_peer,
    bmp_rm: *const BmpMessageValueOpaque,
) -> BgpUpdateResult {
    let bmp_value = unsafe { bmp_rm.as_ref().unwrap().value() };

    let bmp_rm = match bmp_value {
        BmpMessageValue::RouteMonitoring(rm) => rm,
        _ => {
            return BgpUpdateError::WrongBmpMessageType(WrongBmpMessageTypeError(
                bmp_value.get_type().into(),
            ))
                .into();
        }
    };

    let bgp_msg = bmp_rm.update_message();
    let update = match bgp_msg {
        BgpMessage::Update(update) => update,
        _ => {
            return BgpUpdateError::WrongBgpMessageType(WrongBgpMessageTypeError(
                bgp_msg.get_type().into(),
            ))
                .into();
        }
    };

    let mut packets = Vec::with_capacity(update.withdraw_routes().len() + update.nlri().len());

    let mut mp_reach = None;
    let mut mp_unreach = None;

    let mut attr = bgp_attr {
        aspath: ptr::null_mut(),
        community: ptr::null_mut(),
        ecommunity: ptr::null_mut(),
        lcommunity: ptr::null_mut(),
        refcnt: 0, // TODO see how this works in pmacct (prob. intern/unintern)
        rpki_maxlen: 0,
        nexthop: in_addr::default(),
        mp_nexthop: host_addr::default(),
        med: 0,        // uninit protected with bitmap
        local_pref: 0, // uninit protected with bitmap
        origin: BGP_ORIGIN_UNKNOWN as u8,
        bitmap: 0,
    };

    let mut attr_extra = bgp_attr_extra {
        bitmap: 0,
        rd: rd_as {
            type_: 0,
            as_: 0,
            val: 0,
        },
        label: [0, 0, 0],
        path_id: 0,
        aigp: 0,
        psid_li: 0, // TODO not supported in netgauze?
        otc: 0,
    };

    let mut as_path = ptr::null_mut();
    let mut as4_path = ptr::null_mut();

    // TODO free allocated C structs on error
    // TODO accept only one path attribute of each kind, error if multiple
    for _attr in update.path_attributes() {
        match _attr.value() {
            PathAttributeValue::AsPath(aspath) => {
                let extended_length = _attr.extended_length();
                let mut bytes = Vec::with_capacity(aspath.len(extended_length));
                let bytes = {
                    let skip_length_offset = AsPath::BASE_LENGTH + usize::from(extended_length);
                    let mut writer = BufWriter::new(&mut bytes);
                    let _ = aspath.write(&mut writer, extended_length); // todo handle error
                    drop(writer);
                    bytes.split_at(skip_length_offset).1
                };

                as_path = unsafe {
                    // no need to intern as aspath_parse interns as well
                    aspath_parse(
                        peer,
                        bytes.as_ptr() as *mut i8,
                        bytes.len(),
                        !peer.read().cap_4as.is_null() as i32,
                    )
                };

                attr.aspath = reconcile_as24path(as_path, as4_path);
            }
            PathAttributeValue::As4Path(as4path) => {
                let extended_length = _attr.extended_length();
                let mut bytes = Vec::with_capacity(as4path.len(extended_length));
                let bytes = {
                    let skip_length_offset = As4Path::BASE_LENGTH + usize::from(extended_length);
                    let mut writer = BufWriter::new(&mut bytes);
                    let _ = as4path.write(&mut writer, extended_length); // todo handle error
                    drop(writer);
                    bytes.split_at(skip_length_offset).1
                };

                as4_path = unsafe {
                    // no need to intern as aspath_parse interns as well
                    aspath_parse(
                        peer,
                        bytes.as_ptr() as *mut i8,
                        bytes.len(),
                        !peer.read().cap_4as.is_null() as i32,
                    )
                };

                attr.aspath = reconcile_as24path(as_path, as4_path);
            }
            PathAttributeValue::Communities(communities) => {
                let com = unsafe { community_new(peer) };

                for community in communities.communities() {
                    unsafe {
                        community_add_val(peer, com, community.value());
                    }
                }

                attr.community = unsafe {
                    community_intern(peer, com)
                };
            }
            PathAttributeValue::LargeCommunities(large_communities) => {
                let lcom = unsafe { lcommunity_new(peer) };

                for lcommunity in large_communities.communities() {
                    let mut val = lcommunity.to_lcommunity_val();
                    unsafe {
                        lcommunity_add_val(peer, lcom, &mut val as *mut lcommunity_val);
                    }
                }

                attr.lcommunity = unsafe {
                    lcommunity_intern(peer, lcom)
                };
            }
            PathAttributeValue::ExtendedCommunities(extended_communities) => {
                let ecom = unsafe { ecommunity_new(peer) };

                for ecommunity in extended_communities.communities() {
                    let mut val = ecommunity.to_ecommunity_val();
                    unsafe {
                        ecommunity_add_val(peer, ecom, &mut val as *mut ecommunity_val);
                    }
                }

                attr.ecommunity = unsafe {
                    ecommunity_intern(peer, ecom)
                };
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

            // TODO error if already present
            PathAttributeValue::MpReach(mp_reach_attr) => {
                if let Some(_) = mp_reach.replace(mp_reach_attr) {
                    pmacct_log(LogPriority::Warning, "[pmacct-gauze] warn! multiple mp_reach is not supported. ignoring previous mp_reach.\n")
                }
            }
            PathAttributeValue::MpUnreach(mp_unreach_attr) => {
                if let Some(_) = mp_unreach.replace(mp_unreach_attr) {
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
            | PathAttributeValue::UnknownAttribute(_) => pmacct_log(
                LogPriority::Warning,
                &format!(
                    "[pmacct-gauze] warn! attribute type {} is not supported by pmacct\n",
                    _attr
                        .get_type()
                        .map(|__attr| __attr as u8)
                        .unwrap_or_else(|unknown| unknown.code())
                ),
            ),
        };
    }

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

    fn fill_mpls_label(attr_extra: &mut bgp_attr_extra, label_stack: &Vec<MplsLabel>) {
        let bos = label_stack
            .iter()
            .rev()
            .filter(|label| label.is_bottom())
            .next();

        attr_extra.label = if let Some(bos) = bos {
            bos.value().clone()
        } else {
            [0, 0, 0]
        }
    }

    fn fill_rd(attr_extra: &mut bgp_attr_extra, rd: RouteDistinguisher) {
        attr_extra.rd = rd.into();
        attr_extra.rd.set_pmacct_rd_origin(RdOriginType::BGP);
    }

    fn cleanup_mp_reach(attr: &mut bgp_attr, attr_extra: &mut bgp_attr_extra) {
        attr.nexthop = in_addr::default();
        attr.mp_nexthop = host_addr::default();

        attr_extra.path_id = 0;
        attr_extra.label = [0, 0, 0];
        attr_extra.rd = rd_t {
            type_: 0,
            as_: 0,
            val: 0,
        };
    }

    if let Some(mp_reach) = mp_reach {
        // TODO explicit netgauze->pmacct conversion to ensure values will stay the same
        let afi = mp_reach.get_afi() as afi_t;
        let safi = mp_reach.get_safi() as safi_t;
        let update_type = BGP_NLRI_UPDATE;

        match mp_reach {
            // pmacct only has AFI IPv4/6 & BGP-LS
            // and SAFI UNICAST MPLS-LABEL MPLS-VPN
            MpReach::Ipv4Unicast {
                next_hop,
                nlri: nlris,
            } => {
                fill_attr_ipv4_next_hop(&mut attr, next_hop, true);

                for nlri in nlris {
                    fill_path_id(&mut attr_extra, nlri.path_id());

                    packets.push(ProcessPacket {
                        update_type,
                        prefix: prefix::from(&nlri.network().address()),
                        attr,
                        attr_extra,
                        afi,
                        safi,
                    });
                }
            }
            MpReach::Ipv4NlriMplsLabels {
                next_hop,
                nlri: nlris,
            } => {
                fill_attr_mp_next_hop(&mut attr, next_hop);

                for nlri in nlris {
                    fill_path_id(&mut attr_extra, nlri.path_id());
                    fill_mpls_label(&mut attr_extra, nlri.labels());

                    packets.push(ProcessPacket {
                        update_type,
                        prefix: prefix::from(&nlri.prefix()),
                        attr,
                        attr_extra,
                        afi,
                        safi,
                    });
                }
            }
            MpReach::Ipv4MplsVpnUnicast {
                next_hop,
                nlri: nlris,
            } => {
                fill_attr_mp_next_hop(&mut attr, &next_hop.get_addr());

                for nlri in nlris {
                    fill_path_id(&mut attr_extra, nlri.path_id());
                    fill_mpls_label(&mut attr_extra, nlri.label_stack());
                    fill_rd(&mut attr_extra, nlri.rd());

                    packets.push(ProcessPacket {
                        update_type,
                        prefix: prefix::from(&nlri.network().address()),
                        attr,
                        attr_extra,
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
                fill_attr_ipv6_next_hop(&mut attr, next_hop_global);

                for nlri in nlris {
                    fill_path_id(&mut attr_extra, nlri.path_id());

                    packets.push(ProcessPacket {
                        update_type,
                        prefix: prefix::from(&nlri.network().address()),
                        attr,
                        attr_extra,
                        afi,
                        safi,
                    });
                }
            }
            MpReach::Ipv6NlriMplsLabels {
                next_hop,
                nlri: nlris,
            } => {
                fill_attr_mp_next_hop(&mut attr, next_hop);

                for nlri in nlris {
                    fill_path_id(&mut attr_extra, nlri.path_id());
                    fill_mpls_label(&mut attr_extra, nlri.labels());

                    packets.push(ProcessPacket {
                        update_type,
                        prefix: prefix::from(&nlri.prefix()),
                        attr,
                        attr_extra,
                        afi,
                        safi,
                    })
                }
            }
            MpReach::Ipv6MplsVpnUnicast {
                next_hop,
                nlri: nlris,
            } => {
                fill_attr_mp_next_hop(&mut attr, &next_hop.get_addr());

                for nlri in nlris {
                    fill_path_id(&mut attr_extra, nlri.path_id());
                    fill_mpls_label(&mut attr_extra, nlri.label_stack());
                    fill_rd(&mut attr_extra, nlri.rd());

                    packets.push(ProcessPacket {
                        update_type,
                        prefix: prefix::from(&nlri.network().address()),
                        attr,
                        attr_extra,
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
            | MpReach::Unknown { .. } => {
                pmacct_log(LogPriority::Warning, &format!("[pmacct-gauze] warn! received mp_reach with unsupported or unknown afi/safi {}/{} address type {:?}\n",
                                                          mp_reach.get_afi(), mp_reach.get_safi(), mp_reach.get_address_type()));
            }
        }
    }

    cleanup_mp_reach(&mut attr, &mut attr_extra);

    if let Some(mp_unreach) = mp_unreach {
        // TODO explicit netgauze->pmacct conversion to ensure values will stay the same
        let afi = mp_unreach.get_afi() as afi_t;
        let safi = mp_unreach.get_safi() as safi_t;
        let update_type = BGP_NLRI_WITHDRAW;

        match mp_unreach {
            // pmacct only has AFI IPv4/6 & BGP-LS
            // and SAFI UNICAST MPLS-LABEL MPLS-VPN
            MpUnreach::Ipv4Unicast { nlri: nlris } => {
                for nlri in nlris {
                    fill_path_id(&mut attr_extra, nlri.path_id());

                    packets.push(ProcessPacket {
                        update_type,
                        prefix: prefix::from(&nlri.network().address()),
                        attr,
                        attr_extra,
                        afi,
                        safi,
                    });
                }
            }
            MpUnreach::Ipv4NlriMplsLabels { nlri: nlris } => {
                for nlri in nlris {
                    fill_path_id(&mut attr_extra, nlri.path_id());
                    fill_mpls_label(&mut attr_extra, nlri.labels());

                    packets.push(ProcessPacket {
                        update_type,
                        prefix: prefix::from(&nlri.prefix()),
                        attr,
                        attr_extra,
                        afi,
                        safi,
                    });
                }
            }
            MpUnreach::Ipv4MplsVpnUnicast { nlri: nlris } => {
                for nlri in nlris {
                    fill_path_id(&mut attr_extra, nlri.path_id());
                    fill_mpls_label(&mut attr_extra, nlri.label_stack());
                    fill_rd(&mut attr_extra, nlri.rd());

                    packets.push(ProcessPacket {
                        update_type,
                        prefix: prefix::from(&nlri.network().address()),
                        attr,
                        attr_extra,
                        afi,
                        safi,
                    })
                }
            }
            MpUnreach::Ipv6Unicast { nlri: nlris } => {
                for nlri in nlris {
                    fill_path_id(&mut attr_extra, nlri.path_id());

                    packets.push(ProcessPacket {
                        update_type,
                        prefix: prefix::from(&nlri.network().address()),
                        attr,
                        attr_extra,
                        afi,
                        safi,
                    })
                }
            }
            MpUnreach::Ipv6NlriMplsLabels { nlri: nlris } => {
                for nlri in nlris {
                    fill_path_id(&mut attr_extra, nlri.path_id());
                    fill_mpls_label(&mut attr_extra, nlri.labels());

                    packets.push(ProcessPacket {
                        update_type,
                        prefix: prefix::from(&nlri.prefix()),
                        attr,
                        attr_extra,
                        afi,
                        safi,
                    })
                }
            }
            MpUnreach::Ipv6MplsVpnUnicast { nlri: nlris } => {
                for nlri in nlris {
                    fill_path_id(&mut attr_extra, nlri.path_id());
                    fill_mpls_label(&mut attr_extra, nlri.label_stack());
                    fill_rd(&mut attr_extra, nlri.rd());

                    packets.push(ProcessPacket {
                        update_type,
                        prefix: prefix::from(&nlri.network().address()),
                        attr,
                        attr_extra,
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
            | MpUnreach::Unknown { .. } => {
                pmacct_log(LogPriority::Warning, &format!("[pmacct-gauze] warn! received mp_unreach with unsupported or unknown afi/safi {}/{} address type {:?}\n",
                                                          mp_unreach.get_afi(), mp_unreach.get_safi(), mp_unreach.get_address_type()));
            }
        }
    }

    // handle EoR
    if update.nlri().is_empty() && update.withdraw_routes().is_empty() {
        let afi_safi = if update.path_attributes().is_empty() {
            Some((AFI_IP as afi_t, SAFI_UNICAST as safi_t))
        } else if mp_unreach.is_some() {
            Some((mp_unreach.unwrap().get_afi() as afi_t, mp_unreach.unwrap().get_safi() as safi_t))
        } else {
            None // TODO make error
        };

        if let Some((afi, safi)) = afi_safi {
            packets.push(ProcessPacket {
                update_type: 0,
                afi,
                safi,
                prefix: prefix::from(&Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 0).unwrap()),
                attr,
                attr_extra,
            });
        }
    };

    unsafe {
        BgpUpdateResult::Ok(ParsedBgpUpdate {
            update_count: packets
                .iter()
                .filter(|x| x.update_type == BGP_NLRI_UPDATE)
                .count(),
            packets: CSlice::from_vec(packets),
        })
    }
}
