use std::collections::HashSet;
use std::net::IpAddr;
use std::ptr::null_mut;
use std::slice;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use pmacct_gauze_bindings::{bgp_info, bgp_peer, bgp_route_next, bgp_select_misc_db, bgp_table, bgp_table_top, bmp_peer};

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

    // TODO use route table to do longest and shortest prefix lookup for mspi
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
            site.links.eq(link_set)
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

pub unsafe fn prefix_link_discovery(peer: *mut bgp_peer, table: *const bgp_table) -> PrefixLinksMap {
    let mut map = PrefixLinksMap::default();
    let bms = *bgp_select_misc_db((*peer).type_);

    let root = bgp_table_top(peer, table);

    // TODO filter for a VPN client based on community
    let vpn_comm = 0;

    let mut node = root;
    while !node.is_null() {
        let route = *node;

        let modulo = if let Some(callback) = bms.route_info_modulo {
            callback(peer, null_mut(), null_mut(), null_mut(), bms.table_per_peer_buckets)
        } else {
            0
        };

        for peer_buckets in 0..bms.table_per_peer_buckets as usize {
            let position = peer_buckets + modulo as usize;
            let mut ri = *(route.info.add(position) as *mut *mut bgp_info);

            while !ri.is_null() {
                let info = ri.as_ref().unwrap();
                let path_peer = info.peer.as_ref().unwrap();

                // Filter path by VPN ID
                let belongs_to_vpn_client = {
                    if let Some(attr) = info.attr.as_ref()
                        && let Some(comm) = attr.community.as_ref() {
                        let slice = slice::from_raw_parts(comm.val, comm.size as usize);
                        slice.iter().any(|comm| *comm == vpn_comm)
                    } else { false }
                };

                if !belongs_to_vpn_client { continue; }

                let learnt_from_bmp = (path_peer.bmp_se as *mut bmp_peer).as_ref().unwrap();
                let learnt_from_bmp_bgp = &learnt_from_bmp.self_;

                // TODO ensure that PE is the origin PE of the route

                println!("route {:#?}", &route.p);
                let pe = learnt_from_bmp_bgp.addr;
                let ce = path_peer.id;
                let link = Link {
                    pe: RouterId(IpAddr::try_from(&pe).unwrap()),
                    ce: RouterId(IpAddr::try_from(&ce).unwrap()),
                };

                match IpNet::try_from(&route.p).unwrap() {
                    IpNet::V4(prefix) => {
                        println!("prefix {:#?}", prefix);
                        if let Some(links) = map.prefixes_v4.lookup_mut(&prefix) {
                            println!("adding link {:#?}", link);
                            links.insert(link);
                        } else {
                            map.prefixes_v4.insert(prefix.clone(), HashSet::from([link]));
                            println!("new link set {:#?}", map.prefixes_v4.lookup(&prefix));
                        }
                    }
                    IpNet::V6(prefix) => {
                        println!("prefix {:#?}", prefix);
                        if let Some(links) = map.prefixes_v6.lookup_mut(&prefix) {
                            println!("adding link {:#?}", link);
                            links.insert(link);
                        } else {
                            map.prefixes_v6.insert(prefix.clone(), HashSet::from([link]));
                            println!("new link set {:#?}", map.prefixes_v6.lookup(&prefix));
                        }
                    }
                };

                ri = info.next;
            }
        }

        node = bgp_route_next(peer, node);
    }

    map
}
