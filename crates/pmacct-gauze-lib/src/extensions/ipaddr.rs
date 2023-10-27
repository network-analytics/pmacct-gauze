use std::mem::transmute;
use std::net::{IpAddr, Ipv4Addr};
use netgauze_bgp_pkt::wire::serializer::IpAddrWritingError;
use pmacct_gauze_bindings::{AFI_IP, AFI_IP6, bgp_afi2family, in6_addr, in6_addr__bindgen_ty_1, in_addr, prefix, prefix__bindgen_ty_1, u_char};
use std::os::raw::c_int;
use ipnet::{Ipv4Net, Ipv6Net};

#[repr(transparent)]
#[derive(Default)]
pub struct IpAddrBytes(pub [u32; 4]);

impl IpAddrBytes {
    #[allow(dead_code)]
    pub fn ipv4_u32(&self) -> u32 {
        self.0[3]
    }
}

pub trait ExtendIpAddr {
    fn to_bytes(&self) -> Result<IpAddrBytes, IpAddrWritingError>;
}

impl ExtendIpAddr for IpAddr {
    fn to_bytes(&self) -> Result<IpAddrBytes, IpAddrWritingError> {

        let value = match self {
            IpAddr::V4(ipv4) => {
                ipv4.to_bits() as u128
            }
            IpAddr::V6(ipv6) => {
                ipv6.to_bits()
            }
        };

        let result = unsafe { transmute(value) };

        Ok(IpAddrBytes(result))
    }
}

#[repr(transparent)]
pub struct PmacctPrefix(pub prefix);

impl TryFrom<&Ipv4Net> for PmacctPrefix {
    type Error = IpAddrWritingError;

    fn try_from(value: &Ipv4Net) -> Result<Self, Self::Error> {
        let pfx = prefix {
            family: unsafe { bgp_afi2family(AFI_IP as c_int) } as u_char,
            prefixlen: value.prefix_len(),
            __bindgen_padding_0: 0,
            u: prefix__bindgen_ty_1 {
                prefix4: in_addr {
                    s_addr: value.addr().to_bits(),
                }
            },
        };

        Ok(Self(pfx))
    }
}

impl TryFrom<&Ipv6Net> for PmacctPrefix {
    type Error = IpAddrWritingError;

    fn try_from(value: &Ipv6Net) -> Result<Self, Self::Error> {
        let pfx = prefix {
            family: unsafe { bgp_afi2family(AFI_IP6 as c_int) } as u_char,
            prefixlen: value.prefix_len(),
            __bindgen_padding_0: 0,
            u: prefix__bindgen_ty_1 {
                prefix6: in6_addr {
                    __in6_u: in6_addr__bindgen_ty_1 {
                        __u6_addr8: value.addr().octets()
                    }
                }
            },
        };

        Ok(Self(pfx))
    }
}