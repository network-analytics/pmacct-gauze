use netgauze_bgp_pkt::path_attribute::MpReach;
use netgauze_iana::address_family::{AddressFamily, AddressType, SubsequentAddressFamily};

pub trait ExtendMpReach {
    fn get_address_type(&self) -> Option<AddressType>;
    fn get_afi(&self) -> AddressFamily;
    fn get_safi(&self) -> SubsequentAddressFamily;
}

impl ExtendMpReach for MpReach {
    fn get_address_type(&self) -> Option<AddressType> {
        Some(match self {
            MpReach::Ipv4Unicast { .. } => AddressType::Ipv4Unicast,
            MpReach::Ipv4Multicast { .. } => AddressType::Ipv4Multicast,
            MpReach::Ipv4NlriMplsLabels { .. } => AddressType::Ipv4NlriMplsLabels,
            MpReach::Ipv4MplsVpnUnicast { .. } => AddressType::Ipv4MplsLabeledVpn,
            MpReach::Ipv6Unicast { .. } => AddressType::Ipv6Unicast,
            MpReach::Ipv6Multicast { .. } => AddressType::Ipv6Multicast,
            MpReach::Ipv6NlriMplsLabels { .. } => AddressType::Ipv6NlriMplsLabels,
            MpReach::Ipv6MplsVpnUnicast { .. } => AddressType::Ipv6MplsLabeledVpn,
            MpReach::L2Evpn { .. } => AddressType::L2VpnBgpEvpn,
            MpReach::RouteTargetMembership { .. } => AddressType::RouteTargetConstrains, // TODO check if same?
            MpReach::Unknown { .. } => return None
        })
    }

    fn get_afi(&self) -> AddressFamily {
        match self {
            MpReach::Ipv4Unicast { .. } => AddressFamily::IPv4,
            MpReach::Ipv4Multicast { .. } => AddressFamily::IPv4,
            MpReach::Ipv4NlriMplsLabels { .. } => AddressFamily::IPv4,
            MpReach::Ipv4MplsVpnUnicast { .. } => AddressFamily::IPv4,
            MpReach::Ipv6Unicast { .. } => AddressFamily::IPv6,
            MpReach::Ipv6Multicast { .. } => AddressFamily::IPv6,
            MpReach::Ipv6NlriMplsLabels { .. } => AddressFamily::IPv6,
            MpReach::Ipv6MplsVpnUnicast { .. } => AddressFamily::IPv6,
            MpReach::L2Evpn { .. } => AddressFamily::L2vpn,
            MpReach::RouteTargetMembership { .. } => AddressFamily::IPv4,
            MpReach::Unknown { afi, .. } => *afi
        }
    }

    fn get_safi(&self) -> SubsequentAddressFamily {
        match self {
            MpReach::Ipv4Unicast { .. } => SubsequentAddressFamily::Unicast,
            MpReach::Ipv4Multicast { .. } => SubsequentAddressFamily::Multicast,
            MpReach::Ipv4NlriMplsLabels { .. } => SubsequentAddressFamily::NlriMplsLabels,
            MpReach::Ipv4MplsVpnUnicast { .. } => SubsequentAddressFamily::MplsVpn,
            MpReach::Ipv6Unicast { .. } => SubsequentAddressFamily::Unicast,
            MpReach::Ipv6Multicast { .. } => SubsequentAddressFamily::Multicast,
            MpReach::Ipv6NlriMplsLabels { .. } => SubsequentAddressFamily::NlriMplsLabels,
            MpReach::Ipv6MplsVpnUnicast { .. } => SubsequentAddressFamily::MplsVpn,
            MpReach::L2Evpn { .. } => SubsequentAddressFamily::BgpEvpn,
            MpReach::RouteTargetMembership { .. } => SubsequentAddressFamily::RouteTargetConstrains,
            MpReach::Unknown { safi, .. } => *safi
        }
    }
}