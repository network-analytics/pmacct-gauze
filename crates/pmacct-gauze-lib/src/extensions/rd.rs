use netgauze_bgp_pkt::nlri::RouteDistinguisher;
use netgauze_bgp_pkt::wire::serializer::nlri::RouteDistinguisherWritingError;
use netgauze_parse_utils::WritablePdu;
use pmacct_gauze_bindings::{in_addr, rd_as, rd_as4, rd_ip, rd_t};
use std::io::BufWriter;
use std::mem::transmute;

#[repr(transparent)]
#[derive(Default)]
pub struct RouteDistinguisherBytes(pub [u8; 8]);

pub trait ExtendRd {
    fn to_bytes(&self) -> Result<RouteDistinguisherBytes, RouteDistinguisherWritingError>;
    fn to_rd_t(&self) -> rd_t;
}

impl ExtendRd for RouteDistinguisher {
    fn to_bytes(&self) -> Result<RouteDistinguisherBytes, RouteDistinguisherWritingError> {
        let mut result = [0u8; 8];
        {
            let mut writer = BufWriter::new(&mut result[..]);
            self.write(&mut writer)?;
        }

        Ok(RouteDistinguisherBytes(result))
    }

    fn to_rd_t(&self) -> rd_t {
        let type_ = self.get_type() as u16;
        match self {
            RouteDistinguisher::As2Administrator { asn2, number } => unsafe {
                transmute(rd_as {
                    type_,
                    as_: *asn2,
                    val: *number,
                })
            },
            RouteDistinguisher::Ipv4Administrator { ip, number } => unsafe {
                transmute(rd_ip {
                    type_,
                    ip: in_addr {
                        s_addr: ip.to_bits(),
                    },
                    val: *number,
                })
            },
            RouteDistinguisher::As4Administrator { asn4, number } => unsafe {
                transmute(rd_as4 {
                    type_,
                    as_: *asn4,
                    val: *number,
                })
            },
            RouteDistinguisher::LeafAdRoutes => unsafe {
                transmute(rd_as {
                    type_: u16::MAX,
                    as_: u16::MAX,
                    val: u32::MAX,
                })
            },
        }
    }
}
