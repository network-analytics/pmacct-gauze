use netgauze_bmp_pkt::{BmpMessage, BmpMessageValue, BmpPeerType, PeerHeader};

use pmacct_gauze_bindings::{
    bmp_peer_hdr, BMP_RIB_ADJ_RIB_IN_POST, BMP_RIB_ADJ_RIB_IN_PRE, BMP_RIB_ADJ_RIB_OUT_POST,
    BMP_RIB_ADJ_RIB_OUT_PRE, BMP_RIB_LOC_RIB,
};

use crate::capi::bmp::parse::BmpParseError;
use crate::extensions::ipaddr::{ExtendIpAddr, IpAddrBytes};
use crate::extensions::rd::{ExtendRouteDistinguisher, RouteDistinguisherBytes};

pub trait ExtendBmpMessage {
    fn get_peer_header(&self) -> Option<&PeerHeader>;
    fn get_pmacct_peer_hdr(&self) -> Result<Option<bmp_peer_hdr>, BmpParseError>;
}

impl ExtendBmpMessage for BmpMessage {
    fn get_peer_header(&self) -> Option<&PeerHeader> {
        match self {
            BmpMessage::V3(value) => value.get_peer_header(),
        }
    }

    fn get_pmacct_peer_hdr(&self) -> Result<Option<bmp_peer_hdr>, BmpParseError> {
        match self {
            BmpMessage::V3(value) => value.get_pmacct_peer_hdr(),
        }
    }
}

impl ExtendBmpMessage for BmpMessageValue {
    fn get_peer_header(&self) -> Option<&PeerHeader> {
        match self {
            BmpMessageValue::RouteMonitoring(msg) => Some(msg.peer_header()),
            BmpMessageValue::RouteMirroring(msg) => Some(msg.peer_header()),
            BmpMessageValue::StatisticsReport(msg) => Some(msg.peer_header()),
            BmpMessageValue::PeerDownNotification(msg) => Some(msg.peer_header()),
            BmpMessageValue::PeerUpNotification(msg) => Some(msg.peer_header()),

            BmpMessageValue::Initiation(_)
            | BmpMessageValue::Termination(_)
            | BmpMessageValue::Experimental251(_)
            | BmpMessageValue::Experimental252(_)
            | BmpMessageValue::Experimental253(_)
            | BmpMessageValue::Experimental254(_) => None,
        }
    }

    fn get_pmacct_peer_hdr(&self) -> Result<Option<bmp_peer_hdr>, BmpParseError> {
        let peer_hdr = if let Some(peer_hdr) = self.get_peer_header() {
            peer_hdr
        } else {
            return Ok(None);
        };

        Ok(Some(bmp_peer_hdr {
            type_: peer_hdr.peer_type().get_type().into(),
            flags: peer_hdr.peer_type().get_flags_value(),
            rd: peer_hdr
                .rd()
                .map(|rd| rd.to_bytes())
                .unwrap_or(Ok(RouteDistinguisherBytes::default()))?
                .0,
            addr: peer_hdr
                .address()
                .map(|addr| addr.to_bytes())
                .unwrap_or(IpAddrBytes::default())
                .0,
            asn: peer_hdr.peer_as(),
            bgp_id: u32::from_ne_bytes(peer_hdr.bgp_id().octets()),
            tstamp_sec: peer_hdr
                .timestamp()
                .map(|timestamp| timestamp.timestamp() as u32)
                .unwrap_or(0),
            tstamp_usec: peer_hdr
                .timestamp()
                .map(|timestamp| timestamp.timestamp_subsec_micros())
                .unwrap_or(0),
        }))
    }
}

pub trait ExtendBmpPeerHeader {
    fn is_v6(&self) -> Option<bool>;
    fn is_post(&self) -> Option<bool>;
    fn is_out(&self) -> Option<bool>;
    fn is_filtered(&self) -> Option<bool>;
    fn is_loc(&self) -> bool;
    fn rib_type(&self) -> Option<BmpRibType>;
}

// That will go in Netgauze
pub enum BmpRibType {
    AdjRibInPrePolicy,
    AdjRibInPostPolicy,
    LocalRib,
    AdjRibOutPrePolicy,
    AdjRibOutPostPolicy,
}

impl From<BmpRibType> for u8 {
    fn from(value: BmpRibType) -> Self {
        match value {
            BmpRibType::AdjRibInPrePolicy => BMP_RIB_ADJ_RIB_IN_PRE as u8,
            BmpRibType::AdjRibInPostPolicy => BMP_RIB_ADJ_RIB_IN_POST as u8,
            BmpRibType::LocalRib => BMP_RIB_LOC_RIB as u8,
            BmpRibType::AdjRibOutPrePolicy => BMP_RIB_ADJ_RIB_OUT_PRE as u8,
            BmpRibType::AdjRibOutPostPolicy => BMP_RIB_ADJ_RIB_OUT_POST as u8,
        }
    }
}

impl ExtendBmpPeerHeader for PeerHeader {
    fn is_v6(&self) -> Option<bool> {
        match self.peer_type() {
            BmpPeerType::GlobalInstancePeer { ipv6, .. } => Some(ipv6),
            BmpPeerType::RdInstancePeer { ipv6, .. } => Some(ipv6),
            BmpPeerType::LocalInstancePeer { ipv6, .. } => Some(ipv6),
            BmpPeerType::LocRibInstancePeer { .. } => None,
            BmpPeerType::Experimental251 { .. } => None,
            BmpPeerType::Experimental252 { .. } => None,
            BmpPeerType::Experimental253 { .. } => None,
            BmpPeerType::Experimental254 { .. } => None,
        }
    }

    fn is_post(&self) -> Option<bool> {
        match self.peer_type() {
            BmpPeerType::GlobalInstancePeer { post_policy, .. } => Some(post_policy),
            BmpPeerType::RdInstancePeer { post_policy, .. } => Some(post_policy),
            BmpPeerType::LocalInstancePeer { post_policy, .. } => Some(post_policy),
            BmpPeerType::LocRibInstancePeer { .. } => None,
            BmpPeerType::Experimental251 { .. } => None,
            BmpPeerType::Experimental252 { .. } => None,
            BmpPeerType::Experimental253 { .. } => None,
            BmpPeerType::Experimental254 { .. } => None,
        }
    }

    fn is_out(&self) -> Option<bool> {
        match self.peer_type() {
            BmpPeerType::GlobalInstancePeer { adj_rib_out, .. } => Some(adj_rib_out),
            BmpPeerType::RdInstancePeer { adj_rib_out, .. } => Some(adj_rib_out),
            BmpPeerType::LocalInstancePeer { adj_rib_out, .. } => Some(adj_rib_out),
            BmpPeerType::LocRibInstancePeer { .. } => None,
            BmpPeerType::Experimental251 { .. } => None,
            BmpPeerType::Experimental252 { .. } => None,
            BmpPeerType::Experimental253 { .. } => None,
            BmpPeerType::Experimental254 { .. } => None,
        }
    }

    fn is_filtered(&self) -> Option<bool> {
        match self.peer_type() {
            BmpPeerType::GlobalInstancePeer { .. } => None,
            BmpPeerType::RdInstancePeer { .. } => None,
            BmpPeerType::LocalInstancePeer { .. } => None,
            BmpPeerType::LocRibInstancePeer { filtered } => Some(filtered),
            BmpPeerType::Experimental251 { .. } => None,
            BmpPeerType::Experimental252 { .. } => None,
            BmpPeerType::Experimental253 { .. } => None,
            BmpPeerType::Experimental254 { .. } => None,
        }
    }

    fn is_loc(&self) -> bool {
        matches!(self.peer_type(), BmpPeerType::LocRibInstancePeer { .. })
    }

    fn rib_type(&self) -> Option<BmpRibType> {
        if self.is_loc() {
            return Some(BmpRibType::LocalRib);
        }

        let post = self.is_post()?;

        match (self.is_out(), post) {
            (Some(false), false) => Some(BmpRibType::AdjRibInPrePolicy),
            (Some(false), true) => Some(BmpRibType::AdjRibInPostPolicy),
            (Some(true), false) => Some(BmpRibType::AdjRibOutPrePolicy),
            (Some(true), true) => Some(BmpRibType::AdjRibOutPostPolicy),
            (None, _) => None,
        }
    }
}
