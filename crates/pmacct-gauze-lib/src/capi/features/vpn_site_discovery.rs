use std::{mem, slice};
use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use pmacct_gauze_bindings::{bgp_info, BGP_MSG_EXTRA_DATA_BMP, bgp_peer, bgp_route_next, bgp_select_misc_db, bgp_table, bgp_table_top, bmp_chars, bmp_peer, BMP_PEER_TYPE_L3VPN};
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
        prefix_link_discovery(bmp_peer as *mut bgp_peer, bmp_table)
    };
    println!("prefix link = {:#?}", prefix_link);

    let sites = group_pfx_of_same_link_set(prefix_link);
    println!("sites = {:#?}", sites);
}

#[derive(Eq, PartialEq, Hash, Debug, Clone)]
pub struct RouterId(IpAddr);

#[derive(Eq, PartialEq, Hash, Debug, Clone)]
pub struct Link {
    pe: RouterId,
    ce: RouterId,
}

#[derive(Debug)]
pub struct Site {
    links: HashSet<Link>,
    prefixes_v4: RibPrefixTree<Ipv4Net, ()>,
    prefixes_v6: RibPrefixTree<Ipv6Net, ()>,
}

impl Site {
    pub fn new(links: HashSet<Link>, prefixes: Option<Vec<IpNet>>) -> Self {
        let mut new = Self {
            links,
            prefixes_v4: Default::default(),
            prefixes_v6: Default::default(),
        };

        if let Some(vec) = prefixes {
            for prefix in vec {
                match prefix {
                    IpNet::V4(prefix) => new.prefixes_v4.insert(prefix, ()),
                    IpNet::V6(prefix) => new.prefixes_v6.insert(prefix, ())
                }
            }
        }

        new
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
            link_set.is_subset(&site.links)
                ||
                // if this prefix is a subnet of a known prefix it is part of the same site
                site.is_mspi(&net)
        });

        if let Some(site) = site {
            site.prefixes_v4.insert(prefix.clone(), ());
        } else {
            sites.push(Site::new(link_set.clone(), Some(vec![net])));
        }
    });

    prefix_link.prefixes_v6.walk(|prefix, link_set| {
        let net = IpNet::V6(prefix.clone());
        let site = sites.iter_mut().find(|site| {
            // if we already know this link set then the prefix is part of the same site
            site.links.eq(link_set)
                ||
                // if this prefix is a subnet of a known prefix it is part of the same site
                site.is_mspi(&net)
        });

        if let Some(site) = site {
            site.prefixes_v6.insert(prefix.clone(), ());
        } else {
            sites.push(Site::new(link_set.clone(), Some(vec![net])));
        }
    });
    sites
}

// Discover prefixes in the route table and the links that advertise them
pub unsafe fn prefix_link_discovery(peer: *mut bgp_peer, table: *const bgp_table) -> PrefixLinksMap {
    let mut map = PrefixLinksMap::default();

    let bms = *bgp_select_misc_db((*peer).type_);

    // Create dummy bgp_peer to read the RIB
    let mut reader: bgp_peer = mem::zeroed();
    reader.type_ = FUNC_TYPE_BMP as i32;

    // TODO filter for a VPN client based on community, if this is None then do not filter
    let vpn_filter = None;

    // Walk the prefix tree
    let mut node = bgp_table_top(&mut reader, table);
    while !node.is_null() {
        let route = node.as_ref().unwrap();

        let prefix = IpNet::try_from(&route.p).unwrap();

        // Walk route information (paths)
        // We want to look at all paths in the rib so we iterate in all buckets peer_buckets * per_peer_buckets)
        let route_info_table = slice::from_raw_parts(route.info as *mut *mut bgp_info, (bms.table_per_peer_buckets * bms.table_peer_buckets) as usize);
        for bucket in route_info_table {

            // In a bucket we have a linked-list of paths, iterate over it
            let mut ri = *bucket;
            while !ri.is_null() {
                let info = ri.as_ref().unwrap();
                let path_peer = info.peer.as_ref().unwrap();

                // Filter path by VPN ID
                let belongs_to_vpn_client = {
                    if let Some(attr) = info.attr.as_ref()
                        && let Some(comm) = attr.community.as_ref()
                        && let Some(vpn_comm) = vpn_filter {
                        let slice = slice::from_raw_parts(comm.val, comm.size as usize);
                        slice.iter().any(|comm| *comm == vpn_comm)
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

                // Build the link information based on the path info
                let learnt_from_bmp = (path_peer.bmp_se as *mut bmp_peer).as_ref().unwrap();
                let learnt_from_bmp_bgp = &learnt_from_bmp.self_;

                // The PE is the source of the BMP message
                let pe = learnt_from_bmp_bgp.addr;
                // The CE is the peer we learnt the path from
                let ce = path_peer.id;
                let link = Link {
                    pe: RouterId(IpAddr::try_from(&pe).unwrap()),
                    ce: RouterId(IpAddr::try_from(&ce).unwrap()),
                };

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

                ri = info.next;
            }
        }

        node = bgp_route_next(&mut reader, node);
    }

    map
}
