use netgauze_bgp_pkt::wire::serializer::IpAddrWritingError;
use netgauze_bgp_pkt::wire::serializer::nlri::RouteDistinguisherWritingError;
use netgauze_bmp_pkt::{BmpMessage, BmpMessageValue, PeerHeader};
use pmacct_gauze_bindings::bmp_peer_hdr;
use crate::error::ParseError;
use crate::extensions::ipaddr::{ExtendIpAddr, IpAddrBytes};
use crate::extensions::rd::{ExtendRd, RouteDistinguisherBytes};

pub trait ExtendBmpMessage {
    fn get_peer_header(&self) -> Option<&PeerHeader>;
    fn get_pmacct_peer_hdr(&self) -> Result<Option<bmp_peer_hdr>, ParseError>;
}

impl ExtendBmpMessage for BmpMessage {
    fn get_peer_header(&self) -> Option<&PeerHeader> {
        match self {
            BmpMessage::V3(value) => match value {
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
    }

    fn get_pmacct_peer_hdr(&self) -> Result<Option<bmp_peer_hdr>, ParseError> {
        let peer_hdr = if let Some(peer_hdr) = self.get_peer_header() {
            peer_hdr
        } else {
            return Ok(None);
        };

        Ok(Some(bmp_peer_hdr {
            type_: peer_hdr.peer_type().get_type().into(),
            flags: peer_hdr.peer_type().get_flags_value(),
            rd: peer_hdr.rd().map(|rd| rd.to_bytes()).unwrap_or(Ok(RouteDistinguisherBytes::default()))?.0,
            addr: peer_hdr.address().map(|addr| addr.to_bytes()).unwrap_or(IpAddrBytes::default()).0,
            asn: *peer_hdr.peer_as(),
            bgp_id: u32::from_ne_bytes(peer_hdr.bgp_id().octets()),
            tstamp_sec: peer_hdr.timestamp().map(|timestamp| timestamp.timestamp() as u32).unwrap_or(0),
            tstamp_usec: peer_hdr.timestamp().map(|timestamp| timestamp.timestamp_subsec_micros()).unwrap_or(0),
        }))
    }
}

impl From<RouteDistinguisherWritingError> for ParseError {
    fn from(_: RouteDistinguisherWritingError) -> Self {
        Self::RouteDistinguisherError
    }
}

impl From<IpAddrWritingError> for ParseError {
    fn from(_: IpAddrWritingError) -> Self { Self::IpAddrError }
}