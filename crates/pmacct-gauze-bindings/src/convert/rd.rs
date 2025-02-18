use std::mem::transmute;
use std::net::Ipv4Addr;

use netgauze_bgp_pkt::nlri::RouteDistinguisher;

use crate::{
    bgp_rd_type_get, in_addr, rd_as, rd_as4, rd_ip, rd_t, DefaultZeroed, RD_TYPE_AS, RD_TYPE_AS4,
    RD_TYPE_IP,
};

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
                transmute::<rd_ip, rd_as>(rd_ip {
                    type_,
                    ip: in_addr::from(&ip),
                    val: number,
                })
            },
            RouteDistinguisher::As4Administrator { asn4, number } => unsafe {
                transmute::<rd_as4, rd_as>(rd_as4 {
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
            RouteDistinguisher::As2Administrator {
                asn2: value.as_,
                number: value.val,
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

impl DefaultZeroed for rd_t {}
