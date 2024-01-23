use netgauze_bgp_pkt::path_attribute::{MpReach, MpUnreach};
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
            MpReach::RouteTargetMembership { .. } => AddressType::RouteTargetConstrains,
            MpReach::Unknown { .. } => return None,
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
            MpReach::Unknown { afi, .. } => *afi,
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
            MpReach::Unknown { safi, .. } => *safi,
        }
    }
}

impl ExtendMpReach for MpUnreach {
    fn get_address_type(&self) -> Option<AddressType> {
        Some(match self {
            MpUnreach::Ipv4Unicast { .. } => AddressType::Ipv4Unicast,
            MpUnreach::Ipv4Multicast { .. } => AddressType::Ipv4Multicast,
            MpUnreach::Ipv4NlriMplsLabels { .. } => AddressType::Ipv4NlriMplsLabels,
            MpUnreach::Ipv4MplsVpnUnicast { .. } => AddressType::Ipv4MplsLabeledVpn,
            MpUnreach::Ipv6Unicast { .. } => AddressType::Ipv6Unicast,
            MpUnreach::Ipv6Multicast { .. } => AddressType::Ipv6Multicast,
            MpUnreach::Ipv6NlriMplsLabels { .. } => AddressType::Ipv6NlriMplsLabels,
            MpUnreach::Ipv6MplsVpnUnicast { .. } => AddressType::Ipv6MplsLabeledVpn,
            MpUnreach::L2Evpn { .. } => AddressType::L2VpnBgpEvpn,
            MpUnreach::RouteTargetMembership { .. } => AddressType::RouteTargetConstrains,
            MpUnreach::Unknown { .. } => return None,
        })
    }

    fn get_afi(&self) -> AddressFamily {
        match self {
            MpUnreach::Ipv4Unicast { .. } => AddressFamily::IPv4,
            MpUnreach::Ipv4Multicast { .. } => AddressFamily::IPv4,
            MpUnreach::Ipv4NlriMplsLabels { .. } => AddressFamily::IPv4,
            MpUnreach::Ipv4MplsVpnUnicast { .. } => AddressFamily::IPv4,
            MpUnreach::Ipv6Unicast { .. } => AddressFamily::IPv6,
            MpUnreach::Ipv6Multicast { .. } => AddressFamily::IPv6,
            MpUnreach::Ipv6NlriMplsLabels { .. } => AddressFamily::IPv6,
            MpUnreach::Ipv6MplsVpnUnicast { .. } => AddressFamily::IPv6,
            MpUnreach::L2Evpn { .. } => AddressFamily::L2vpn,
            MpUnreach::RouteTargetMembership { .. } => AddressFamily::IPv4,
            MpUnreach::Unknown { afi, .. } => *afi,
        }
    }

    fn get_safi(&self) -> SubsequentAddressFamily {
        match self {
            MpUnreach::Ipv4Unicast { .. } => SubsequentAddressFamily::Unicast,
            MpUnreach::Ipv4Multicast { .. } => SubsequentAddressFamily::Multicast,
            MpUnreach::Ipv4NlriMplsLabels { .. } => SubsequentAddressFamily::NlriMplsLabels,
            MpUnreach::Ipv4MplsVpnUnicast { .. } => SubsequentAddressFamily::MplsVpn,
            MpUnreach::Ipv6Unicast { .. } => SubsequentAddressFamily::Unicast,
            MpUnreach::Ipv6Multicast { .. } => SubsequentAddressFamily::Multicast,
            MpUnreach::Ipv6NlriMplsLabels { .. } => SubsequentAddressFamily::NlriMplsLabels,
            MpUnreach::Ipv6MplsVpnUnicast { .. } => SubsequentAddressFamily::MplsVpn,
            MpUnreach::L2Evpn { .. } => SubsequentAddressFamily::BgpEvpn,
            MpUnreach::RouteTargetMembership { .. } => {
                SubsequentAddressFamily::RouteTargetConstrains
            }
            MpUnreach::Unknown { safi, .. } => *safi,
        }
    }
}
