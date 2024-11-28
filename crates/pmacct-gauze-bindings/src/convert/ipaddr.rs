use std::ffi::c_int;
use std::mem::transmute;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{
    bgp_afi2family, host_addr, host_addr__bindgen_ty_1, prefix, prefix__bindgen_ty_1,
    DefaultZeroed, AFI_IP, AFI_IP6,
};
use ipnet::{IpNet, Ipv4Net, Ipv6Net, PrefixLenError};

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

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash)]
pub struct AddrFamilyError;

impl TryFrom<&host_addr> for IpAddr {
    /// BAD FAMILY VALUE
    type Error = AddrFamilyError;

    fn try_from(value: &host_addr) -> Result<Self, Self::Error> {
        match value.family as i32 {
            libc::AF_INET => unsafe {
                Ok(IpAddr::V4(Ipv4Addr::from(value.address.ipv4)))
            }
            libc::AF_INET6 => unsafe {
                Ok(IpAddr::V6(Ipv6Addr::from(&value.address.ipv6)))
            }
            _ => {
                Err(AddrFamilyError)
            }
        }
    }
}

#[derive(Debug, Ord, PartialOrd, Eq, PartialEq, Copy, Clone, Hash)]
pub enum PrefixError {
    PrefixLenError,
    AddrFamilyError,
}

impl From<PrefixLenError> for PrefixError {
    fn from(_value: PrefixLenError) -> Self {
        PrefixError::PrefixLenError
    }
}

impl TryFrom<&prefix> for IpNet {
    type Error = PrefixError;

    fn try_from(value: &prefix) -> Result<Self, Self::Error> {
        match value.family as i32 {
            libc::AF_INET => unsafe {
                Ok(IpNet::V4(Ipv4Net::new(Ipv4Addr::from(&value.u.prefix4), value.prefixlen)?))
            }
            libc::AF_INET6 => unsafe {
                Ok(IpNet::V6(Ipv6Net::new(Ipv6Addr::from(&value.u.prefix6), value.prefixlen)?))
            }
            _ => {
                Err(PrefixError::AddrFamilyError)
            }
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
