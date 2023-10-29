use std::ffi::c_int;
use std::net::{Ipv4Addr, Ipv6Addr};
use crate::{AFI_IP, AFI_IP6, bgp_afi2family, host_addr, host_addr__bindgen_ty_1, in6_addr, in6_addr__bindgen_ty_1, in_addr, prefix, prefix__bindgen_ty_1};
use ipnet;
use ipnet::{Ipv4Net, Ipv6Net};

impl From<&Ipv4Addr> for in_addr {
    fn from(value: &Ipv4Addr) -> Self {
        in_addr {
            s_addr: value.to_bits(),
        }
    }
}

impl From<&Ipv4Net> for prefix {
    fn from(value: &Ipv4Net) -> Self {
        prefix {
            family: unsafe { bgp_afi2family(AFI_IP as c_int) } as u8,
            prefixlen: value.prefix_len(),
            __bindgen_padding_0: 0,
            u: prefix__bindgen_ty_1 {
                prefix4: (&value.network()).into()
            },
        }
    }
}

impl From<&Ipv6Addr> for in6_addr {
    fn from(value: &Ipv6Addr) -> Self {
        in6_addr {
            __in6_u: in6_addr__bindgen_ty_1 {
                __u6_addr8: value.octets()
            },
        }
    }
}

impl From<&Ipv6Net> for prefix {
    fn from(value: &Ipv6Net) -> Self {
        prefix {
            family: unsafe { bgp_afi2family(AFI_IP6 as c_int) } as u8,
            prefixlen: value.prefix_len(),
            __bindgen_padding_0: 0,
            u: prefix__bindgen_ty_1 {
                prefix6: (&value.network()).into()
            },
        }
    }
}

impl From<&Ipv6Addr> for host_addr {
    fn from(value: &Ipv6Addr) -> Self {
        host_addr {
            family: unsafe { bgp_afi2family(AFI_IP6 as c_int) } as u8,
            address: host_addr__bindgen_ty_1 {
                ipv6: value.into()
            },
        }
    }
}

impl From<&Ipv4Addr> for host_addr {
    fn from(value: &Ipv4Addr) -> Self {
        host_addr {
            family: unsafe { bgp_afi2family(AFI_IP6 as c_int) } as u8,
            address: host_addr__bindgen_ty_1 {
                ipv4: value.into()
            },
        }
    }
}

impl Default for in_addr {
    fn default() -> Self {
        in_addr {
            s_addr: 0,
        }
    }
}

impl Default for in6_addr {
    fn default() -> Self {
        in6_addr {
            __in6_u: in6_addr__bindgen_ty_1 {
                __u6_addr8: [0u8; 16]
            },
        }
    }
}

impl Default for host_addr {
    fn default() -> Self {
        host_addr {
            family: 0,
            // use the ipv6 union variant because it's the biggest the whole union size
            address: host_addr__bindgen_ty_1 {
                ipv6: in6_addr::default()
            },
        }
    }
}