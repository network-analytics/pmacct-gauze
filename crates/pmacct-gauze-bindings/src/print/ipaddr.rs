use std::fmt::{Debug, Display, Error, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};
use crate::{host_addr, in6_addr, in_addr};
use libc::{c_int, AF_INET, AF_INET6};


// TODO move ip conversions to crate::convert
impl Display for in_addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&Ipv4Addr::from_bits(self.s_addr), f)
    }
}


impl Display for in6_addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        unsafe {
            Display::fmt(&Ipv6Addr::from(self.__in6_u.__u6_addr8), f)
        }
    }
}

impl Debug for in6_addr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("in6_addr");

        unsafe {
            debug.field("__in6_u", &self.__in6_u.__u6_addr8);
            debug.field("__in6_u(as Ipv6)", &self.to_string());
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
                    debug.field("address.unknown!", &self.address.ipv6.__in6_u.__u6_addr8);
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
                Display::fmt(&Ipv4Addr::from_bits(self.address.ipv4.s_addr), f)
            }
            AF_INET6 => unsafe {
                Display::fmt(&Ipv6Addr::from(self.address.ipv6.__in6_u.__u6_addr8), f)
            }
            _ => {
                return Err(Error)
            }
        }
    }
}