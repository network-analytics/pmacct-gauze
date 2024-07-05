use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::ptr::null_mut;

use ipnet::IpNet;

use pmacct_gauze_bindings::{bgp_info, bgp_peer, bgp_route_next, bgp_select_misc_db, bgp_table, bgp_table_top, bmp_peer};

// TODO handle different AFI/SAFI

pub type PrefixLinksMap = HashMap<IpNet, HashSet<Link>>;

#[no_mangle]
pub extern "C" fn vsd_find_sites(bmp_peer: *const bmp_peer, bmp_table: *const bgp_table) {
    let prefix_link = unsafe {
        prefix_link_discovery(bmp_peer as *mut bgp_peer, bmp_table)
    };
    println!("prefix link = {:#?}", prefix_link);

    let sites = group_pfx_of_same_link_set(prefix_link);
    println!("sites = {:#?}", sites);
}

#[derive(Eq, PartialEq, Hash, Debug)]
pub struct RouterId(IpAddr);

#[derive(Eq, PartialEq, Hash, Debug)]
pub struct Link {
    pe: RouterId,
    ce: RouterId,
}

#[derive(Eq, PartialEq, Debug)]
pub struct Site {
    links: HashSet<Link>,
    prefixes: HashSet<IpNet>,
}

impl Site {
    // TODO use route table to do longest and shortest prefix lookup for mspi
    pub fn is_mspi(&self, _prefix: &IpNet) -> bool {
        false
    }
}

pub fn group_pfx_of_same_link_set(prefix_link: PrefixLinksMap) -> Vec<Site> {
    let mut sites = Vec::<Site>::new();

    for (prefix, link_set) in prefix_link {
        let site = sites.iter_mut().find(|site| {
            // if we already know this link set then the prefix is part of the same site
            site.links == link_set
                ||
                // if this prefix is a subnet or supernet of a known prefix it is part of the same site{
                site.is_mspi(&prefix)
        });

        if let Some(site) = site {
            site.prefixes.insert(prefix);
        } else {
            sites.push(Site {
                links: link_set,
                prefixes: HashSet::from([prefix]),
            });
        }
    }

    sites
}

pub unsafe fn prefix_link_discovery(peer: *mut bgp_peer, table: *const bgp_table) -> PrefixLinksMap {
    let mut map = PrefixLinksMap::new();
    let bms = *bgp_select_misc_db((*peer).type_);

    let root = bgp_table_top(peer, table);

    // TODO filter for a VPN client based on community

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
                let info = *ri;
                let path_peer = *info.peer;

                let learnt_from_bmp = path_peer.bmp_se as *mut bmp_peer;
                let learnt_from_bmp_bgp = &(*learnt_from_bmp).self_;

                if learnt_from_bmp_bgp as *const bgp_peer == peer {
                    let pe = learnt_from_bmp_bgp.addr;
                    let ce = path_peer.id;

                    map.entry(IpNet::try_from(&route.p).unwrap()).or_default().insert(Link {
                        pe: RouterId(IpAddr::try_from(&pe).unwrap()),
                        ce: RouterId(IpAddr::try_from(&ce).unwrap()),
                    });
                }

                ri = info.next;
            }
        }

        node = bgp_route_next(peer, node);
    }

    map
}
