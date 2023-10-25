use netgauze_bgp_pkt::iana::PathAttributeType;
use netgauze_bgp_pkt::path_attribute::{PathAttribute, PathAttributeValue, UnknownAttribute};

pub trait ExtendBgpAttribute {
    fn get_type(&self) -> Result<PathAttributeType, UnknownAttribute> ;
}

impl ExtendBgpAttribute for PathAttribute {
    fn get_type(&self) -> Result<PathAttributeType, UnknownAttribute> {
        let type_code = match self.value() {
            PathAttributeValue::Origin(_) => PathAttributeType::Origin,
            PathAttributeValue::AsPath(_) => PathAttributeType::AsPath,
            PathAttributeValue::As4Path(_) => PathAttributeType::As4Path,
            PathAttributeValue::NextHop(_) => PathAttributeType::NextHop,
            PathAttributeValue::MultiExitDiscriminator(_) => PathAttributeType::MultiExitDiscriminator,
            PathAttributeValue::LocalPreference(_) => PathAttributeType::LocalPreference,
            PathAttributeValue::AtomicAggregate(_) => PathAttributeType::AtomicAggregate,
            PathAttributeValue::Aggregator(_) => PathAttributeType::Aggregator,
            PathAttributeValue::Communities(_) => PathAttributeType::Communities,
            PathAttributeValue::ExtendedCommunities(_) => PathAttributeType::ExtendedCommunities,
            PathAttributeValue::ExtendedCommunitiesIpv6(_) => PathAttributeType::ExtendedCommunitiesIpv6,
            PathAttributeValue::LargeCommunities(_) => PathAttributeType::LargeCommunities,
            PathAttributeValue::Originator(_) => PathAttributeType::OriginatorId,
            PathAttributeValue::ClusterList(_) => PathAttributeType::ClusterList,
            PathAttributeValue::MpReach(_) => PathAttributeType::MpReachNlri,
            PathAttributeValue::MpUnreach(_) => PathAttributeType::MpUnreachNlri,
            PathAttributeValue::UnknownAttribute(unknown) => return Err(unknown.clone()),
        };

        Ok(type_code)
    }
}