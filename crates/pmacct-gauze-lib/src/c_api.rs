use std::collections::HashMap;
use std::ffi::CString;
use libc;
use netgauze_bmp_pkt::{BmpMessage, BmpMessageValue, InitiationInformation};
use netgauze_parse_utils::{Span, WritablePdu};
use nom::Offset;
use pmacct_gauze_bindings::{bmp_common_hdr, bmp_peer_hdr, bmp_log_tlv, prefix, bgp_attr, bgp_attr_extra, BGP_NLRI_UPDATE, AFI_IP, SAFI_UNICAST, afi_t, safi_t, BGP_NLRI_WITHDRAW, in_addr, host_addr, host_addr__bindgen_ty_1, rd_as, bgp_peer, in6_addr, in6_addr__bindgen_ty_1, path_id_t, BGP_BMAP_ATTR_MULTI_EXIT_DISC, BGP_BMAP_ATTR_LOCAL_PREF, BGP_ORIGIN_UNKNOWN, rd_t};
use netgauze_parse_utils::ReadablePduWithOneInput;
use std::{ptr, slice};
use std::fmt::{Debug, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use netgauze_bgp_pkt::BgpMessage;
use netgauze_bgp_pkt::nlri::MplsLabel;
use netgauze_bgp_pkt::path_attribute::{MpReach, MpUnreach, PathAttributeValue};
use crate::error::ParseError;
use crate::extensions::bgp_attribute::ExtendBgpAttribute;
use crate::extensions::bmp_message::ExtendBmpMessage;
use crate::extensions::initiation_information::TlvExtension;
use crate::extensions::mp_reach::ExtendMpReach;
use crate::extensions::next_hop::ExtendLabeledNextHop;
use crate::extensions::rd::ExtendRd;
use crate::macros::free_cslice_t;
use crate::option::COption;
use crate::slice::CSlice;

pub struct BmpMessageValueOpaque(BmpMessageValue);

#[no_mangle]
pub extern "C" fn netgauze_print_packet(buffer: *const libc::c_char, len: u32) -> u32 {
    let s = unsafe { slice::from_raw_parts(buffer as *const u8, len as usize) };
    let span = Span::new(s);
    if let Ok((end_span, msg)) = BmpMessage::from_wire(span, &HashMap::new()) {
        println!("span: ptr: {:?} | value {:?}", span.as_ptr(), span);
        println!("msg: {:?}", msg);
        return span.offset(&end_span) as u32;
    }

    0
}

#[repr(C)]
pub struct ParsedBmp {
    common_header: bmp_common_hdr,
    peer_header: COption<bmp_peer_hdr>,
    pub message: *mut BmpMessageValueOpaque,
}

#[repr(C)]
pub struct ParseOk<T> {
    read_bytes: u32,
    pub parsed: T,
}

#[repr(C)]
pub enum ParseResultEnum<T> {
    ParseSuccess(ParseOk<T>),
    ParseFailure(ParseError),
}


#[no_mangle]
pub extern "C" fn netgauze_parse_packet(buffer: *const libc::c_char, buf_len: u32) -> ParseResultEnum<ParsedBmp> {
    let s = unsafe { slice::from_raw_parts(buffer as *const u8, buf_len as usize) };
    let span = Span::new(s);
    let result = BmpMessage::from_wire(span, &HashMap::new());
    if let Ok((end_span, msg)) = result {
        let read_bytes = span.offset(&end_span) as u32;

        // println!("netgauze {} bytes read", read_bytes);

        return ParseResultEnum::ParseSuccess(ParseOk {
            read_bytes,
            parsed: ParsedBmp {
                common_header: bmp_common_hdr {
                    version: msg.get_version().into(),
                    len: read_bytes,
                    type_: msg.get_type().into(),
                },
                peer_header: msg.get_pmacct_peer_hdr()?.into(),
                message: Box::into_raw(Box::new(match msg {
                    BmpMessage::V3(value) => BmpMessageValueOpaque(value)
                })),
            },
        });
    }

    let err = result.err().unwrap();

    let netgauze_error = CString::new(err.to_string()).unwrap();

    ParseError::NetgauzeError(netgauze_error.into_raw()).into()
}


#[no_mangle]
pub extern "C" fn bmp_init_get_tlvs(bmp_init: *const BmpMessageValueOpaque) -> CSlice<bmp_log_tlv> {
    let bmp_init = unsafe { &bmp_init.as_ref().unwrap().0 };

    let init = match bmp_init {
        BmpMessageValue::Initiation(init) => init,
        _ => unreachable!() // TODO make it an error
    };

    let mut tlvs = Vec::<bmp_log_tlv>::with_capacity(init.information().len());

    for tlv in init.information() {
        tlvs.push(bmp_log_tlv {
            pen: 0,
            type_: tlv.get_type().into(),
            len: (tlv.len() - InitiationInformation::BASE_LENGTH) as u16,
            val: tlv.get_value_ptr(),
        })
    }

    let c_slice = unsafe {
        CSlice::from_vec(tlvs)
    };

    // println!("bmp_init_get_tlvs: {:#?}", &c_slice);

    c_slice
}

free_cslice_t!(bmp_log_tlv);

/// pmacct C code MUST reallocate and copy all values
/// that need freeing to ensure safe memory freeing from C
#[repr(C)]
pub struct ProcessPacket {
    update_type: u32,
    afi: afi_t,
    safi: safi_t,
    prefix: prefix,
    attr: bgp_attr,
    attr_extra: bgp_attr_extra,
}

#[repr(transparent)]
struct DebugUpdateType(u32);

impl Debug for DebugUpdateType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", match self.0 {
            BGP_NLRI_UPDATE => "BGP_NLRI_UPDATE",
            BGP_NLRI_WITHDRAW => "BGP_NLRI_WITHDRAW",
            _ => "BGP_NLRI_UNDEFINED",
        }, self.0)
    }
}

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

// TODO use ParseError
#[no_mangle]
pub extern "C" fn netgauze_bgp_parse_nlri(_peer: *mut bgp_peer, bmp_rm: *const BmpMessageValueOpaque) -> COption<CSlice<ProcessPacket>> {
    let bmp_rm = unsafe { bmp_rm.as_ref().unwrap() };

    let bmp_rm = match &bmp_rm.0 {
        BmpMessageValue::RouteMonitoring(rm) => {
            rm
        }
        _ => unreachable!()
    };


    let mut result = Vec::with_capacity(bmp_rm.updates().len());

    for update in bmp_rm.updates() {
        let update = match update {
            BgpMessage::Update(update) => update,
            _ => unreachable!()
        };

        let mut mp_reach = None;
        let mut mp_unreach = None;

        let mut attr = bgp_attr {
            aspath: ptr::null_mut(), // TODO figure out a solution for cached values
            community: ptr::null_mut(), // TODO figure out a solution for cached values
            ecommunity: ptr::null_mut(), // TODO figure out a solution for cached values
            lcommunity: ptr::null_mut(), // TODO figure out a solution for cached values
            refcnt: 0, // TODO see how this works in pmacct (prob. intern/unintern)
            flag: 0,
            nexthop: in_addr { s_addr: 0 },
            mp_nexthop: host_addr {
                family: 0,
                address: host_addr__bindgen_ty_1 {
                    ipv6: in6_addr {
                        __in6_u: in6_addr__bindgen_ty_1 {
                            __u6_addr32: [0, 0, 0, 0]
                        }
                    }
                },
            },
            med: 0, // uninit protected with bitmap
            local_pref: 0, // uninit protected with bitmap
            origin: BGP_ORIGIN_UNKNOWN as u8,
            bitmap: 0,
        };

        let mut attr_extra = bgp_attr_extra {
            bitmap: 0, // TODO set BGP_BMAP_ATTR_AIGP when AIGP supported in netgauze
            rd: rd_as {
                type_: 0,
                as_: 0,
                val: 0,
            },
            label: [0, 0, 0],
            path_id: 0,
            aigp: 0, // TODO not supported in netgauze?
            psid_li: 0, // TODO not supported in netgauze?
            otc: 0, // TODO not supported in netgauze?
        };

        for _attr in update.path_attributes() {
            match _attr.value() {
                // TODO pointer references need to get them from a cache but
                // the getters expect a raw pointer to the wire bytes
                PathAttributeValue::AsPath(_) => {}
                PathAttributeValue::As4Path(_) => {}
                PathAttributeValue::Communities(_) => {}
                PathAttributeValue::LargeCommunities(_) => {}
                PathAttributeValue::ExtendedCommunities(_) => {}
                PathAttributeValue::ExtendedCommunitiesIpv6(_) => {}

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

                PathAttributeValue::NextHop(next_hop) => attr.nexthop.s_addr = next_hop.next_hop().to_bits(),

                // TODO error if already present
                PathAttributeValue::MpReach(mp_reach_attr) => {
                    if let Some(_) = mp_reach.replace(mp_reach_attr) {
                        println!("[pmacct-gauze] warn! multiple mp_reach is not supported. ignoring previous mp_reach.")
                    }
                }
                PathAttributeValue::MpUnreach(mp_unreach_attr) => {
                    if let Some(_) = mp_unreach.replace(mp_unreach_attr) {
                        println!("[pmacct-gauze] warn! multiple mp_unreach is not supported. ignoring previous mp_unreach.")
                    }
                }

                PathAttributeValue::AtomicAggregate(_)
                | PathAttributeValue::Aggregator(_)
                | PathAttributeValue::Originator(_)
                | PathAttributeValue::ClusterList(_)
                | PathAttributeValue::UnknownAttribute(_) => {
                    println!("[pmacct-gauze] warn! attribute type {} is not supported by pmacct",
                             _attr.get_type()
                                 .map(|__attr| __attr as u8)
                                 .unwrap_or_else(|unknown| unknown.code()))
                }
            };
        }

        fn fill_attr_ipv4_next_hop(attr: &mut bgp_attr, next_hop: &Ipv4Addr, mp_reach: bool) {
            if !mp_reach {
                attr.nexthop = in_addr::from(next_hop);
            } else {
                attr.mp_nexthop = host_addr::from(next_hop);
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
            let bos = label_stack.iter()
                .rev()
                .filter(|label| label.is_bottom())
                .next();

            attr_extra.label = if let Some(bos) = bos {
                bos.value().clone()
            } else {
                [0, 0, 0]
            }
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
                MpReach::Ipv4Unicast { next_hop, nlri: nlris } => {
                    fill_attr_ipv4_next_hop(&mut attr, next_hop, true);

                    for nlri in nlris {
                        fill_path_id(&mut attr_extra, nlri.path_id());

                        result.push(ProcessPacket {
                            update_type,
                            prefix: prefix::from(nlri.network().address()),
                            attr,
                            attr_extra,
                            afi,
                            safi,
                        });
                    }
                }
                MpReach::Ipv4NlriMplsLabels { next_hop, nlri: nlris } => {
                    fill_attr_mp_next_hop(&mut attr, next_hop);

                    for nlri in nlris {
                        fill_path_id(&mut attr_extra, nlri.path_id());
                        fill_mpls_label(&mut attr_extra, nlri.labels());

                        result.push(ProcessPacket {
                            update_type,
                            prefix: prefix::from(&nlri.prefix()),
                            attr,
                            attr_extra,
                            afi,
                            safi,
                        });
                    }
                }
                MpReach::Ipv4MplsVpnUnicast { next_hop, nlri: nlris } => {
                    fill_attr_mp_next_hop(&mut attr, &next_hop.get_addr());

                    for nlri in nlris {
                        fill_path_id(&mut attr_extra, nlri.path_id());
                        fill_mpls_label(&mut attr_extra, nlri.label_stack());

                        attr_extra.rd = nlri.rd().to_rd_t();

                        result.push(ProcessPacket {
                            update_type,
                            prefix: prefix::from(nlri.network().address()),
                            attr,
                            attr_extra,
                            afi,
                            safi,
                        })
                    }
                }
                MpReach::Ipv6Unicast { next_hop_global, next_hop_local: _, nlri: nlris } => {
                    fill_attr_ipv6_next_hop(&mut attr, next_hop_global);

                    for nlri in nlris {
                        fill_path_id(&mut attr_extra, nlri.path_id());

                        result.push(ProcessPacket {
                            update_type,
                            prefix: prefix::from(nlri.network().address()),
                            attr,
                            attr_extra,
                            afi,
                            safi,
                        });
                    }
                }
                MpReach::Ipv6NlriMplsLabels { next_hop, nlri: nlris } => {
                    fill_attr_mp_next_hop(&mut attr, next_hop);

                    for nlri in nlris {
                        fill_path_id(&mut attr_extra, nlri.path_id());
                        fill_mpls_label(&mut attr_extra, nlri.labels());

                        result.push(ProcessPacket {
                            update_type,
                            prefix: prefix::from(&nlri.prefix()),
                            attr,
                            attr_extra,
                            afi,
                            safi,
                        })
                    }
                }
                MpReach::Ipv6MplsVpnUnicast { next_hop, nlri: nlris } => {
                    fill_attr_mp_next_hop(&mut attr, &next_hop.get_addr());

                    for nlri in nlris {
                        fill_path_id(&mut attr_extra, nlri.path_id());
                        fill_mpls_label(&mut attr_extra, nlri.label_stack());
                        attr_extra.rd = nlri.rd().to_rd_t();

                        result.push(ProcessPacket {
                            update_type,
                            prefix: prefix::from(nlri.network().address()),
                            attr,
                            attr_extra,
                            afi,
                            safi,
                        })
                    }
                }

                // not supported by pmacct
                MpReach::Ipv4Multicast { .. } => {}
                MpReach::Ipv6Multicast { .. } => {}
                MpReach::L2Evpn { .. } => {}
                MpReach::RouteTargetMembership { .. } => {}
                MpReach::Unknown { .. } => {}
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

                        result.push(ProcessPacket {
                            update_type,
                            prefix: prefix::from(nlri.network().address()),
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

                        result.push(ProcessPacket {
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

                        attr_extra.rd = nlri.rd().to_rd_t();

                        result.push(ProcessPacket {
                            update_type,
                            prefix: prefix::from(nlri.network().address()),
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

                        result.push(ProcessPacket {
                            update_type,
                            prefix: prefix::from(nlri.network().address()),
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

                        result.push(ProcessPacket {
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
                        attr_extra.rd = nlri.rd().to_rd_t();

                        result.push(ProcessPacket {
                            update_type,
                            prefix: prefix::from(nlri.network().address()),
                            attr,
                            attr_extra,
                            afi,
                            safi,
                        })
                    }
                }

                // not supported by pmacct
                MpUnreach::Ipv4Multicast { .. } => {}
                MpUnreach::Ipv6Multicast { .. } => {}
                MpUnreach::L2Evpn { .. } => {}
                MpUnreach::RouteTargetMembership { .. } => {}
                MpUnreach::Unknown { .. } => {}
            }
        }

        for nlri in update.nlri() {
            result.push(ProcessPacket {
                update_type: BGP_NLRI_UPDATE,
                prefix: prefix::from(nlri.network().address()),
                attr,
                attr_extra,
                afi: AFI_IP as afi_t,
                safi: SAFI_UNICAST as safi_t,
            })
        }

        for withdraw in update.withdraw_routes() {
            result.push(ProcessPacket {
                update_type: BGP_NLRI_WITHDRAW,
                prefix: prefix::from(withdraw.network().address()),
                attr,
                attr_extra,
                afi: AFI_IP as afi_t,
                safi: SAFI_UNICAST as safi_t,
            })
        }
    }

    for (idx, packet) in result.iter().enumerate() {
        println!("Packet [{}/{}] {:#?}", idx, result.len() - 1, packet);
    }
    let result = unsafe {
        CSlice::from_vec(result)
    };

    COption::Some(result)
}

free_cslice_t!(ProcessPacket);


#[no_mangle]
pub extern "C" fn nonce10() {}
