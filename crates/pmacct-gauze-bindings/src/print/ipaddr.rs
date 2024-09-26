use crate::{host_addr, in_addr};
use libc::{c_int, AF_INET, AF_INET6};
use std::fmt::{Debug, Display, Error, Formatter};
use std::intrinsics::transmute;
use std::net::{Ipv4Addr, Ipv6Addr};

impl Display for in_addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&Ipv4Addr::from(self), f)
    }
}

impl Display for crate::in6_addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&Ipv6Addr::from(self), f)
    }
}

impl Debug for crate::in6_addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("in6_addr");

        unsafe {
            debug.field("inner bytes", &transmute::<Self, libc::in6_addr>(*self).s6_addr);
            debug.field("inner bytes(as Ipv6)", &self.to_string());
        }

        debug.finish()
    }
}

impl Debug for host_addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("host_addr");

        debug.field("family", &self.family);
        unsafe {
            match self.family as c_int {
                AF_INET => {
                    debug.field("address.ipv4", &self.address.ipv4);
                }
                AF_INET6 => {
                    debug.field("address.ipv6", &self.address.ipv6);
                }
                _ => {
                    debug.field("address.unknown!", &"cannot display");
                }
            }
        }

        debug.finish()
    }
}

impl Display for host_addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.family as i32 {
            AF_INET => unsafe {
                Display::fmt(
                    &Ipv4Addr::from_bits(u32::from_be(self.address.ipv4.s_addr)),
                    f,
                )
            },
            AF_INET6 => unsafe {
                let ipv6 = transmute::<crate::in6_addr, libc::in6_addr>(self.address.ipv6);
                Display::fmt(&Ipv6Addr::from(ipv6.s6_addr), f)
            },
            _ => Err(Error),
        }
    }
}
