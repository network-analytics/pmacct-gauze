use std::ffi::c_int;
use std::mem::transmute;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    bgp_afi2family, host_addr, host_addr__bindgen_ty_1, prefix, prefix__bindgen_ty_1,
    DefaultZeroed, AFI_IP, AFI_IP6,
};
use ipnet::{Ipv4Net, Ipv6Net};

impl From<&Ipv4Addr> for crate::in_addr {
    fn from(value: &Ipv4Addr) -> Self {
        crate::in_addr {
            s_addr: value.to_bits().to_be(),
        }
    }
}

impl From<&crate::in_addr> for Ipv4Addr {
    fn from(value: &crate::in_addr) -> Self {
        (*value).into()
    }
}

impl From<crate::in_addr> for Ipv4Addr {
    fn from(value: crate::in_addr) -> Self {
        Ipv4Addr::from_bits(u32::from_be(value.s_addr))
    }
}

impl From<&Ipv6Addr> for crate::in6_addr {
    fn from(value: &Ipv6Addr) -> Self {
        unsafe {
            transmute::<libc::in6_addr, crate::in6_addr>(libc::in6_addr {
                s6_addr: value.octets(),
            })
        }
    }
}

impl From<&crate::in6_addr> for Ipv6Addr {
    fn from(value: &crate::in6_addr) -> Self {
        let converted = unsafe { transmute::<crate::in6_addr, libc::in6_addr>(*value) };

        Ipv6Addr::from(converted.s6_addr)
    }
}

impl From<&Ipv4Net> for prefix {
    fn from(value: &Ipv4Net) -> Self {
        prefix {
            family: unsafe { bgp_afi2family(AFI_IP as c_int) } as u8,
            prefixlen: value.prefix_len(),
            __bindgen_padding_0: 0,
            u: prefix__bindgen_ty_1 {
                prefix4: (&value.network()).into(),
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
                prefix6: (&value.network()).into(),
            },
        }
    }
}

impl From<&Ipv6Addr> for host_addr {
    fn from(value: &Ipv6Addr) -> Self {
        host_addr {
            family: unsafe { bgp_afi2family(AFI_IP6 as c_int) } as u8,
            address: host_addr__bindgen_ty_1 { ipv6: value.into() },
        }
    }
}

impl From<&Ipv4Addr> for host_addr {
    fn from(value: &Ipv4Addr) -> Self {
        host_addr {
            family: unsafe { bgp_afi2family(AFI_IP as c_int) } as u8,
            address: host_addr__bindgen_ty_1 { ipv4: value.into() },
        }
    }
}

impl From<&IpAddr> for host_addr {
    fn from(value: &IpAddr) -> Self {
        match value {
            IpAddr::V4(v4) => v4.into(),
            IpAddr::V6(v6) => v6.into(),
        }
    }
}

impl host_addr {
    pub fn default_ipv4() -> Self {
        Self {
            family: unsafe { bgp_afi2family(AFI_IP as c_int) } as u8,
            address: host_addr__bindgen_ty_1 {
                ipv4: crate::in_addr::default_zeroed(),
            },
        }
    }

    pub fn default_ipv6() -> Self {
        Self {
            family: unsafe { bgp_afi2family(AFI_IP6 as c_int) } as u8,
            address: host_addr__bindgen_ty_1 {
                ipv6: crate::in6_addr::default_zeroed(),
            },
        }
    }
}

impl prefix {
    pub fn default_ipv4() -> Self {
        Self {
            family: unsafe { bgp_afi2family(AFI_IP as c_int) } as u8,
            prefixlen: 0,
            __bindgen_padding_0: 0,
            u: prefix__bindgen_ty_1 {
                prefix4: crate::in_addr::default_zeroed(),
            },
        }
    }

    pub fn default_ipv6() -> Self {
        Self {
            family: unsafe { bgp_afi2family(AFI_IP6 as c_int) } as u8,
            prefixlen: 0,
            __bindgen_padding_0: 0,
            u: prefix__bindgen_ty_1 {
                prefix6: crate::in6_addr::default_zeroed(),
            },
        }
    }
}

impl DefaultZeroed for prefix {}
impl DefaultZeroed for host_addr {}
impl DefaultZeroed for crate::in6_addr {}
impl DefaultZeroed for crate::in_addr {}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use crate::in_addr;

    #[test]
    fn in_addr_from_ipv4_addr() {
        let ip = Ipv4Addr::new(254, 1, 128, 127);
        let _other = in_addr::from(&ip);
    }
}
