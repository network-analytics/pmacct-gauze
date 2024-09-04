use std::{mem, slice};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use netgauze_bgp_pkt::community::Community;

use pmacct_gauze_bindings::{bgp_info, bgp_misc_structs, BGP_MSG_EXTRA_DATA_BMP, bgp_peer, bgp_route_next, bgp_select_misc_db, bgp_table, bgp_table_top, bmp_chars, bmp_peer, BMP_PEER_TYPE_L3VPN};
use pmacct_gauze_bindings::FUNC_TYPE_BMP;

use crate::capi::features::rib::{Rib, RibPrefixTree};

// TODO handle different AFI/SAFI

#[derive(Debug, Default)]
pub struct PrefixLinksMap {
    prefixes_v6: RibPrefixTree<Ipv6Net, HashSet<Link>>,
    prefixes_v4: RibPrefixTree<Ipv4Net, HashSet<Link>>,
}

#[no_mangle]
pub extern "C" fn vsd_find_sites(bmp_peer: *const bmp_peer, bmp_table: *const bgp_table) {
    let prefix_link = unsafe {
        let bms = &*bgp_select_misc_db((*bmp_peer).self_.type_);
        prefix_link_discovery(bms, &*bmp_table)
    };
    println!("prefix link = {:#?}", prefix_link);

    let mut sites = group_pfx_of_same_link_set(prefix_link);
    println!("sites = {:#?}", sites);
}

#[no_mangle]
pub extern "C" fn vsd_find_sites_comms(bmp_peer: *const bmp_peer, bmp_table: *const bgp_table) {
    let mut sites = HashMap::<Community, Site>::new();
    let bms = unsafe { &*bgp_select_misc_db((*bmp_peer).self_.type_) };
    let comm_vpn_site_tag_mask = 3033 << 16;
    let vpn_filter = None;

    unsafe {
        walk_table(bms, &*bmp_table, vpn_filter, |prefix, info| {
            if let Some(attr) = info.attr.as_ref()
                && let Some(comms) = attr.community.as_ref() {
                let comms = slice::from_raw_parts(comms.val, comms.size as usize);

                for comm in comms {
                    let comm = comm.swap_bytes(); // pmacct stores in network byte order
                    if comm & comm_vpn_site_tag_mask == comm_vpn_site_tag_mask {
                        let site = sites.entry(Community::new(comm)).or_insert(Default::default());
                        site.links.insert(make_link(info));
                        site.insert(prefix);
                        site.metadata.insert(SiteMetadata::SiteCommunity(Community::new(comm)));
                        if let Some(vpn_filter) = vpn_filter {
                            site.metadata.insert(SiteMetadata::VpnCommunity(vpn_filter));
                        }
                    }
                }
            }
        });
    }

    println!("sites comm = {:#?}", sites)
}

#[derive(Eq, PartialEq, Hash, Debug, Clone)]
pub struct RouterId(IpAddr);

#[derive(Eq, PartialEq, Hash, Debug, Clone)]
pub struct Link {
    pe: RouterId,
    ce: RouterId,
}

#[derive(Eq, PartialEq, Hash, Debug, Clone)]
pub enum SiteMetadata {
    SiteCommunity(Community),
    VpnCommunity(Community),
}

#[derive(Debug, Default)]
pub struct Site {
    links: HashSet<Link>,
    prefixes_v4: RibPrefixTree<Ipv4Net, ()>,
    prefixes_v6: RibPrefixTree<Ipv6Net, ()>,
    metadata: HashSet<SiteMetadata>,
}

impl Site {
    pub fn new(links: HashSet<Link>, prefixes: Option<Vec<IpNet>>, tags: Option<Vec<SiteMetadata>>) -> Self {
        let mut new = Self {
            links,
            prefixes_v4: Default::default(),
            prefixes_v6: Default::default(),
            metadata: tags.map_or_else(Default::default, HashSet::from_iter),
        };

        if let Some(vec) = prefixes {
            for prefix in vec {
                new.insert(prefix)
            }
        }

        new
    }

    pub fn insert(&mut self, prefix: IpNet) {
        match prefix {
            IpNet::V4(prefix) => self.prefixes_v4.insert(prefix, ()),
            IpNet::V6(prefix) => self.prefixes_v6.insert(prefix, ())
        }
    }

    // Use route table to do longest prefix match for MSPI (More Specific Prefix Injection) detection
    // We only do longest prefix match because routes are inserted in the RIB in less to more specific order
    pub fn is_mspi(&self, prefix: &IpNet) -> bool {
        return match prefix {
            IpNet::V4(prefix) => {
                (&self.prefixes_v4).longest_prefix_match(prefix).is_some()
            }
            IpNet::V6(prefix) => {
                (&self.prefixes_v6).longest_prefix_match(prefix).is_some()
            }
        };
    }
}

pub fn group_pfx_of_same_link_set(prefix_link: PrefixLinksMap) -> Vec<Site> {
    let mut sites = Vec::<Site>::new();

    prefix_link.prefixes_v4.walk(|prefix, link_set| {
        let net = IpNet::V4(prefix.clone());
        let site = sites.iter_mut().find(|site| {
            // if we already know this link set then the prefix is part of the same site
            let subset = link_set.is_subset(&site.links);
            // if this prefix is a subnet of a known prefix it is part of the same site
            let mspi = site.is_mspi(&net);

            subset || mspi
        });

        if let Some(site) = site {
            site.prefixes_v4.insert(prefix.clone(), ());
        } else {
            sites.push(Site::new(link_set.clone(), Some(vec![net]), None));
        }
    });

    prefix_link.prefixes_v6.walk(|prefix, link_set| {
        let net = IpNet::V6(prefix.clone());
        let site = sites.iter_mut().find(|site| {
            // if we already know this link set then the prefix is part of the same site
            let subset = site.links.eq(link_set);
            // if this prefix is a subnet of a known prefix it is part of the same site
            let mspi = site.is_mspi(&net);

            subset || mspi
        });

        if let Some(site) = site {
            site.prefixes_v6.insert(prefix.clone(), ());
        } else {
            sites.push(Site::new(link_set.clone(), Some(vec![net]), None));
        }
    });
    sites
}

// Discover prefixes in the route table and the links that advertise them
pub unsafe fn prefix_link_discovery(bms: &bgp_misc_structs, table: &bgp_table) -> PrefixLinksMap {
    let mut map = PrefixLinksMap::default();

    let vpn_filter = None;

    walk_table(bms, table, vpn_filter, |prefix, info| {
        let link = make_link(info);
        // Based on the prefix we insert in the v4 or v6 RIB
        match prefix {
            IpNet::V4(prefix) => {
                if let Some(links) = map.prefixes_v4.lookup_mut(&prefix) {
                    links.insert(link);
                } else {
                    map.prefixes_v4.insert(prefix.clone(), HashSet::from([link]));
                }
            }
            IpNet::V6(prefix) => {
                if let Some(links) = map.prefixes_v6.lookup_mut(&prefix) {
                    links.insert(link);
                } else {
                    map.prefixes_v6.insert(prefix.clone(), HashSet::from([link]));
                }
            }
        };
    });

    map
}

unsafe fn make_link(info: &bgp_info) -> Link {
    let path_peer = &*info.peer;

    // Build the link information based on the path info
    let learnt_from_bmp = (path_peer.bmp_se as *mut bmp_peer).as_ref().unwrap();
    let learnt_from_bmp_bgp = &learnt_from_bmp.self_;

    // The PE is the source of the BMP message
    let pe = learnt_from_bmp_bgp.addr;
    // The CE is the peer we learnt the path from
    let ce = path_peer.id;
    Link {
        pe: RouterId(IpAddr::try_from(&pe).unwrap()),
        ce: RouterId(IpAddr::try_from(&ce).unwrap()),
    }
}

pub unsafe fn walk_table(bms: &bgp_misc_structs, table: &bgp_table, vpn_filter: Option<Community>, mut apply: impl FnMut(IpNet, &bgp_info)) {

    // Create dummy bgp_peer to read the RIB
    let mut reader: bgp_peer = mem::zeroed();
    reader.type_ = FUNC_TYPE_BMP as i32;

    // Walk the prefix tree
    let mut node = bgp_table_top(&mut reader, table);
    while !node.is_null() {
        let route = node.as_ref().unwrap();

        // Walk route information (paths)
        // We want to look at all paths in the rib so we iterate in all buckets peer_buckets * per_peer_buckets)
        let route_info_table = slice::from_raw_parts(route.info as *mut *mut bgp_info, (bms.table_per_peer_buckets * bms.table_peer_buckets) as usize);
        for bucket in route_info_table {

            // In a bucket we have a linked-list of paths, iterate over it
            let mut ri = *bucket;
            while !ri.is_null() {
                let info = ri.as_ref().unwrap();

                // Filter path by VPN ID
                let belongs_to_vpn_client = {
                    if let Some(attr) = info.attr.as_ref()
                        && let Some(comm) = attr.community.as_ref()
                        && let Some(vpn_comm) = vpn_filter {
                        let slice = slice::from_raw_parts(comm.val, comm.size as usize);
                        slice.iter().any(|comm| *comm == vpn_comm.value())
                    } else {
                        // If we have no filter configured keep all paths
                        vpn_filter.is_none()
                    }
                };

                if !belongs_to_vpn_client {
                    ri = info.next;
                    continue;
                }

                // We want paths that we know were received on a PE-CE link and not on a PE-PE link
                // To do that we only keep adj-rib-in paths since paths from RD Instance Peers
                // (bmp sessions in the client VRF instead of the default VRF)
                assert_eq!(info.bmed.id, BGP_MSG_EXTRA_DATA_BMP as u8);
                if let Some(data) = (info.bmed.data as *const bmp_chars).as_ref() {
                    if data.is_out != 0 || data.is_loc != 0 || data.peer_type != BMP_PEER_TYPE_L3VPN as u8 { // This is not adj-in pre or post
                        ri = info.next;
                        continue;
                    }
                } else {
                    panic!("no bmp data wtf?");
                }

                apply(IpNet::try_from(&route.p).unwrap(), info);

                ri = info.next;
            }
        }

        node = bgp_route_next(&mut reader, node);
    }
}
