use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::IpNet;

/// Very stupid and inefficient ip lookup table that just does the job
/// only does longest prefix check for IP addresses, not networks
/// based on https://rtoch.com/posts/rust-cidr-routing/

pub trait RoutingTable {
    fn insert(&mut self, route: IpNet);
    fn remove(&mut self, route: IpNet);
    fn find_addr_aggregate(&self, addr: IpAddr) -> Option<IpNet>;
    fn find_addr_specific(&self, addr: IpAddr) -> Option<IpNet>;
    fn find_net_aggregate(&self, addr: IpNet) -> Option<IpNet>;
    fn find_parent(&self, route: IpNet) -> Option<IpNet>;
    fn contains(&self, addr: IpNet) -> bool;
}

impl<const N: usize> From<[IpNet; N]> for HashRoutingTable {
    fn from(value: [IpNet; N]) -> Self {
        Self {
            routes: HashSet::from(value),
        }
    }
}

pub const fn max_pfx_len(addr: IpAddr) -> u8 {
    match addr {
        IpAddr::V4(_) => Ipv4Addr::BITS as u8,
        IpAddr::V6(_) => Ipv6Addr::BITS as u8,
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct HashRoutingTable {
    routes: HashSet<IpNet>,
}

impl HashRoutingTable {
    pub fn new() -> Self {
        Self {
            routes: HashSet::new(),
        }
    }

    pub fn find(&self, addr: IpAddr, range_inclusive: impl Iterator<Item=u8>) -> Option<IpNet> {
        for len in range_inclusive {
            let net = IpNet::new(addr, len).unwrap().trunc();

            if self.routes.contains(&net) {
                return Some(net);
            }
        }

        None
    }
}

impl RoutingTable for HashRoutingTable {
    fn insert(&mut self, route: IpNet) {
        self.routes.insert(route.trunc());
    }

    fn remove(&mut self, route: IpNet) {
        self.routes.remove(&route.trunc());
    }

    fn find_addr_aggregate(&self, addr: IpAddr) -> Option<IpNet> {
        self.find(addr, 0..=max_pfx_len(addr))
    }

    fn find_addr_specific(&self, addr: IpAddr) -> Option<IpNet> {
        self.find(addr, (0..=max_pfx_len(addr)).rev())
    }

    fn find_net_aggregate(&self, route: IpNet) -> Option<IpNet> {
        self.find(route.trunc().addr(), 0..route.prefix_len())
    }

    fn find_parent(&self, route: IpNet) -> Option<IpNet> {
        self.find(route.addr(), (0..route.prefix_len()).rev())
    }

    fn contains(&self, addr: IpNet) -> bool {
        self.routes.contains(&addr)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use ipnet::IpNet;

    use crate::capi::features::ip_lookup_table::{HashRoutingTable, RoutingTable};

    #[test]
    pub fn test_basic_table_op() {
        let mut table = HashRoutingTable::new();

        table.insert(IpNet::from_str("10.10.0.0/16").unwrap());
        table.insert(IpNet::from_str("10.10.10.0/24").unwrap());
        table.insert(IpNet::from_str("10.10.11.0/24").unwrap());
        table.insert(IpNet::from_str("10.10.10.10/32").unwrap());
        table.insert(IpNet::from_str("10.10.11.11/32").unwrap());

        assert!(table.contains(IpNet::from_str("10.10.0.0/16").unwrap()));
        assert!(table.contains(IpNet::from_str("10.10.10.0/24").unwrap()));
        assert!(table.contains(IpNet::from_str("10.10.11.0/24").unwrap()));
        assert!(table.contains(IpNet::from_str("10.10.10.10/32").unwrap()));
        assert!(table.contains(IpNet::from_str("10.10.11.11/32").unwrap()));

        assert_eq!(table.find_addr_specific(IpAddr::from_str("10.10.10.10").unwrap()), Some(IpNet::from_str("10.10.10.10/32").unwrap()));
        assert_eq!(table.find_addr_aggregate(IpAddr::from_str("10.10.10.10").unwrap()), Some(IpNet::from_str("10.10.0.0/16").unwrap()));
        assert_eq!(table.find_net_aggregate(IpNet::from_str("10.10.10.0/24").unwrap()), Some(IpNet::from_str("10.10.0.0/16").unwrap()));

        assert_eq!(table.find_addr_specific(IpAddr::from_str("10.10.11.11").unwrap()), Some(IpNet::from_str("10.10.11.11/32").unwrap()));
        assert_eq!(table.find_addr_aggregate(IpAddr::from_str("10.10.11.11").unwrap()), Some(IpNet::from_str("10.10.0.0/16").unwrap()));
        assert_eq!(table.find_net_aggregate(IpNet::from_str("10.10.11.0/24").unwrap()), Some(IpNet::from_str("10.10.0.0/16").unwrap()));

        assert_eq!(table.find_parent(IpNet::from_str("10.10.10.10/32").unwrap()), Some(IpNet::from_str("10.10.10.0/24").unwrap()));
        assert_eq!(table.find_parent(IpNet::from_str("10.10.10.0/24").unwrap()), Some(IpNet::from_str("10.10.0.0/16").unwrap()));
        assert_eq!(table.find_parent(IpNet::from_str("10.10.0.0/16").unwrap()), None);

        table.remove(IpNet::from_str("10.10.0.0/16").unwrap());
        table.remove(IpNet::from_str("10.10.10.0/24").unwrap());
        table.remove(IpNet::from_str("10.10.11.0/24").unwrap());
        table.remove(IpNet::from_str("10.10.10.10/32").unwrap());
        table.remove(IpNet::from_str("10.10.11.11/32").unwrap());

        assert!(!table.contains(IpNet::from_str("10.10.0.0/16").unwrap()));
        assert!(!table.contains(IpNet::from_str("10.10.10.0/24").unwrap()));
        assert!(!table.contains(IpNet::from_str("10.10.11.0/24").unwrap()));
        assert!(!table.contains(IpNet::from_str("10.10.10.10/32").unwrap()));
        assert!(!table.contains(IpNet::from_str("10.10.11.11/32").unwrap()));
    }
}