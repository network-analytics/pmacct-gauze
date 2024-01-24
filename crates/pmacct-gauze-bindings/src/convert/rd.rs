use crate::{in_addr, rd_as, rd_as4, rd_ip, rd_t};
use netgauze_bgp_pkt::nlri::RouteDistinguisher;
use std::intrinsics::transmute;

impl From<RouteDistinguisher> for rd_t {
    fn from(value: RouteDistinguisher) -> Self {
        let type_ = value.get_type() as u16;
        match value {
            RouteDistinguisher::As2Administrator { asn2, number } => rd_as {
                type_,
                as_: asn2,
                val: number,
            },
            RouteDistinguisher::Ipv4Administrator { ip, number } => unsafe {
                transmute(rd_ip {
                    type_,
                    ip: in_addr {
                        s_addr: ip.to_bits(),
                    },
                    val: number,
                })
            },
            RouteDistinguisher::As4Administrator { asn4, number } => unsafe {
                transmute(rd_as4 {
                    type_,
                    as_: asn4,
                    val: number,
                })
            },
            RouteDistinguisher::LeafAdRoutes => rd_as {
                type_: u16::MAX,
                as_: u16::MAX,
                val: u32::MAX,
            },
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for rd_t {
    fn default() -> Self {
        rd_t {
            type_: 0,
            as_: 0,
            val: 0,
        }
    }
}
