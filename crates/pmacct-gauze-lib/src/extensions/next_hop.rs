use std::net::IpAddr;
use netgauze_bgp_pkt::nlri::LabeledNextHop;

pub trait ExtendLabeledNextHop {
    fn get_addr(&self) -> IpAddr;
}

impl ExtendLabeledNextHop for LabeledNextHop {
    fn get_addr(&self) -> IpAddr {
        match self {
            LabeledNextHop::Ipv4(ipv4) => IpAddr::V4(*ipv4.next_hop()),
            LabeledNextHop::Ipv6(ipv6) => IpAddr::V6(*ipv6.next_hop())
        }
    }
}