use crate::{
    bgp_rd_type_get, in_addr, rd_as, rd_as4, rd_ip, rd_t, RD_TYPE_AS, RD_TYPE_AS4, RD_TYPE_IP,
};
use netgauze_bgp_pkt::nlri::RouteDistinguisher;
use std::intrinsics::transmute;
use std::net::Ipv4Addr;

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

impl From<rd_t> for RouteDistinguisher {
    fn from(value: rd_t) -> Self {
        let rd_type = unsafe { bgp_rd_type_get(value.type_) } as u32;

        if rd_type == RD_TYPE_AS {
            let rd_as: rd_as = unsafe { transmute(value) };

            RouteDistinguisher::As2Administrator {
                asn2: rd_as.as_,
                number: rd_as.val,
            }
        } else if rd_type == RD_TYPE_IP {
            let rd_ip: rd_ip = unsafe { transmute(value) };

            RouteDistinguisher::Ipv4Administrator {
                ip: Ipv4Addr::from(rd_ip.ip),
                number: rd_ip.val,
            }
        } else if rd_type == RD_TYPE_AS4 {
            let rd_as4: rd_as4 = unsafe { transmute(value) };

            RouteDistinguisher::As4Administrator {
                asn4: rd_as4.as_,
                number: rd_as4.val,
            }
        } else {
            unreachable!()
            // TODO make error for this, impl TryFrom instead
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
