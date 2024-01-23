use std::mem::transmute;
use std::net::IpAddr;

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
    fn to_bytes(&self) -> IpAddrBytes;
}

impl ExtendIpAddr for IpAddr {
    fn to_bytes(&self) -> IpAddrBytes {
        let result = match self {
            IpAddr::V4(ipv4) => [0, 0, 0, ipv4.to_bits().to_be()],
            IpAddr::V6(ipv6) => unsafe { transmute(ipv6.to_bits().to_be()) },
        };

        IpAddrBytes(result)
    }
}
