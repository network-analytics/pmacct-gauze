use netgauze_bgp_pkt::nlri::{LabeledNextHop, RouteDistinguisher};
use std::net::IpAddr;

pub trait ExtendLabeledNextHop {
    fn get_addr(&self) -> IpAddr;
    fn rd(&self) -> RouteDistinguisher;
}

impl ExtendLabeledNextHop for LabeledNextHop {
    fn get_addr(&self) -> IpAddr {
        match self {
            LabeledNextHop::Ipv4(ipv4) => IpAddr::V4(ipv4.next_hop()),
            LabeledNextHop::Ipv6(ipv6) => IpAddr::V6(ipv6.next_hop()),
        }
    }

    fn rd(&self) -> RouteDistinguisher {
        match self {
            LabeledNextHop::Ipv4(nexthop) => nexthop.rd(),
            LabeledNextHop::Ipv6(nexthop) => nexthop.rd(),
        }
    }
}
