use std::collections::HashMap;
use std::ffi::CString;
use libc;
use netgauze_bmp_pkt::{BmpMessage, BmpMessageValue, InitiationInformation};
use netgauze_parse_utils::{Span, WritablePdu};
use nom::Offset;
use pmacct_gauze_bindings::{bmp_common_hdr, bmp_peer_hdr, bmp_log_tlv, prefix, bgp_attr, bgp_attr_extra, BGP_NLRI_UPDATE, AFI_IP, SAFI_UNICAST, afi_t, safi_t, BGP_NLRI_WITHDRAW, in_addr, host_addr, host_addr__bindgen_ty_1, rd_as, aspath_parse, bgp_peer, bgp_afi2family, AFI_IP6, in6_addr, in6_addr__bindgen_ty_1, SAFI_MPLS_LABEL, path_id_t};
use netgauze_parse_utils::ReadablePduWithOneInput;
use std::{ptr, slice};
use std::net::{IpAddr, Ipv4Addr};
use std::os::raw::c_int;
use netgauze_bgp_pkt::BgpMessage;
use netgauze_bgp_pkt::path_attribute::{MpReach, PathAttributeValue};
use crate::error::ParseError;
use crate::extensions::bmp_message::ExtendBmpMessage;
use crate::extensions::initiation_information::TlvExtension;
use crate::extensions::ipaddr::CPrefix;
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

#[repr(C)]
pub struct ProcessPacket {
    update_type: u32,
    /// pmacct C code MUST reallocate and copy this value
    /// to ensure correct freeing from C
    prefix: prefix,
    /// pmacct C code MUST reallocate and copy this value
    /// to ensure correct freeing from C
    attr: bgp_attr,
    attr_extra: bgp_attr_extra,
    afi: afi_t,
    safi: safi_t,
}

#[no_mangle]
pub extern "C" fn netgauze_bgp_parse_nlri(peer: *mut bgp_peer, bmp_rm: *const BmpMessageValueOpaque) -> COption<CSlice<ProcessPacket>> {
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

        // TODO figure out a solution for cached values
        let _aspath = unsafe {
            aspath_parse(peer, ptr::null_mut(), 10, 1 as c_int)
        };

        let mut attr = bgp_attr {
            aspath: ptr::null_mut(),
            community: ptr::null_mut(),
            ecommunity: ptr::null_mut(),
            lcommunity: ptr::null_mut(),
            refcnt: 0, // TODO see how this works in pmacct (prob. intern/unintern)
            flag: 0, // TODO double check but this seems to be unused in regular bgp (rpki involved?)
            nexthop: in_addr { s_addr: 0 },
            mp_nexthop: host_addr { family: 0, address: host_addr__bindgen_ty_1 { ipv4: in_addr { s_addr: 0 } } },
            med: 0,
            local_pref: 0,
            origin: 0,
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
            psid_li: 0,
            otc: 0,
        };

        // TODO parse attr
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
                PathAttributeValue::MultiExitDiscriminator(med) => attr.med = med.metric(),
                PathAttributeValue::LocalPreference(local_pref) => attr.local_pref = local_pref.metric(),

                PathAttributeValue::NextHop(next_hop) => attr.nexthop.s_addr = next_hop.next_hop().to_bits(),

                // TODO error if already present
                PathAttributeValue::MpReach(mp_reach_attr) => {
                    let _ = mp_reach.insert(mp_reach_attr);
                }
                PathAttributeValue::MpUnreach(mp_unreach_attr) => {
                    let _ = mp_unreach.insert(mp_unreach_attr);
                }

                // TODO warn attribute not supported by pmacct
                PathAttributeValue::AtomicAggregate(_)
                | PathAttributeValue::Aggregator(_)
                | PathAttributeValue::Originator(_)
                | PathAttributeValue::ClusterList(_)
                | PathAttributeValue::UnknownAttribute(_) => {}
            };
        }

        fn fill_attr_ipv4_next_hop(attr: &mut bgp_attr, next_hop: &Ipv4Addr, mp_reach: bool) {
            if !mp_reach {
                attr.nexthop.s_addr = next_hop.to_bits();
            } else {
                attr.mp_nexthop = host_addr {
                    family: unsafe { bgp_afi2family(AFI_IP as c_int) } as u8,
                    address: host_addr__bindgen_ty_1 {
                        ipv4: in_addr {
                            s_addr: next_hop.to_bits()
                        }
                    },
                };
            }
        }

        fn fill_attr_mp_next_hop(attr: &mut bgp_attr, next_hop: &IpAddr) {
            let afi = match next_hop {
                IpAddr::V4(_) => AFI_IP,
                IpAddr::V6(_) => AFI_IP6
            };

            let addr = match next_hop {
                IpAddr::V4(ipv4) => host_addr__bindgen_ty_1 {
                    ipv4: in_addr {
                        s_addr: ipv4.to_bits()
                    }
                },
                IpAddr::V6(ipv6) => host_addr__bindgen_ty_1 {
                    ipv6: in6_addr {
                        __in6_u: in6_addr__bindgen_ty_1 {
                            __u6_addr8: ipv6.octets()
                        }
                    }
                }
            };

            attr.mp_nexthop = host_addr {
                family: unsafe { bgp_afi2family(afi as c_int) } as u8,
                address: addr,
            };
        }

        fn fill_path_id(attr_extra: &mut bgp_attr_extra, path_id: &Option<path_id_t>) {
            if let Some(path_id) = path_id {
                attr_extra.path_id = *path_id;
            }
        }

        // TODO
        if let Some(mp_reach) = mp_reach {
            match mp_reach {
                // pmacct only has AFI IPv4/6 & BGP-LS
                // and SAFI UNICAST MPLS-LABEL MPLS-VPN
                MpReach::Ipv4Unicast { next_hop, nlri: nlris } => {
                    fill_attr_ipv4_next_hop(&mut attr, next_hop, true);

                    for nlri in nlris {
                        fill_path_id(&mut attr_extra, &nlri.path_id());

                        result.push(ProcessPacket {
                            update_type: BGP_NLRI_UPDATE,
                            prefix: CPrefix::try_from(nlri.network().address()).unwrap().0,
                            attr,
                            attr_extra,
                            afi: AFI_IP as afi_t,
                            safi: SAFI_UNICAST as safi_t,
                        });
                    }
                }
                MpReach::Ipv4NlriMplsLabels { next_hop, nlri: nlris } => {
                    fill_attr_mp_next_hop(&mut attr, next_hop);

                    for nlri in nlris {
                        fill_path_id(&mut attr_extra, &nlri.path_id());
                        // TODO label, one in pmacct, multiple in netgauze

                        result.push(ProcessPacket {
                            update_type: BGP_NLRI_UPDATE,
                            prefix: CPrefix::try_from(&nlri.prefix()).unwrap().0,
                            attr,
                            attr_extra,
                            afi: AFI_IP as afi_t,
                            safi: SAFI_MPLS_LABEL as safi_t,
                        });
                    }
                }
                MpReach::Ipv4MplsVpnUnicast { .. } => {}
                MpReach::Ipv6Unicast { .. } => {}
                MpReach::Ipv6NlriMplsLabels { .. } => {}
                MpReach::Ipv6MplsVpnUnicast { .. } => {}


                // not supported by pmacct
                MpReach::Ipv4Multicast { .. } => {}
                MpReach::Ipv6Multicast { .. } => {}
                MpReach::L2Evpn { .. } => {}
                MpReach::RouteTargetMembership { .. } => {}
                MpReach::Unknown { .. } => {}
            }
        }

        for nlri in update.nlri() {
            result.push(ProcessPacket {
                update_type: BGP_NLRI_UPDATE,
                prefix: CPrefix::try_from(nlri.network().address()).unwrap().0,
                attr,
                attr_extra,
                afi: AFI_IP as afi_t,
                safi: SAFI_UNICAST as safi_t,
            })
        }

        for withdraw in update.withdraw_routes() {
            result.push(ProcessPacket {
                update_type: BGP_NLRI_WITHDRAW,
                prefix: CPrefix::try_from(withdraw.network().address()).unwrap().0,
                attr,
                attr_extra,
                afi: AFI_IP as afi_t,
                safi: SAFI_UNICAST as safi_t,
            })
        }
    }

    let result = unsafe {
        CSlice::from_vec(result)
    };

    COption::Some(result)
}

free_cslice_t!(ProcessPacket);


#[no_mangle]
pub extern "C" fn nonce10() {}
