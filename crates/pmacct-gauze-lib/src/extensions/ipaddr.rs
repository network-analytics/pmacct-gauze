use std::mem::transmute;
use std::net::IpAddr;
use netgauze_bgp_pkt::wire::serializer::IpAddrWritingError;

#[repr(transparent)]
#[derive(Default)]
pub struct IpAddrBytes(pub [u32; 4]);

pub trait ExtendIpAddr {
    fn to_bytes(&self) -> Result<IpAddrBytes, IpAddrWritingError>;
}

impl ExtendIpAddr for IpAddr {
    fn to_bytes(&self) -> Result<IpAddrBytes, IpAddrWritingError> {

        let mut result = [0u8; 16];
        {
            match self {
                IpAddr::V4(ipv4) => {
                    result[12..].copy_from_slice(&ipv4.octets());
                }
                IpAddr::V6(ipv6) => {
                    result.copy_from_slice(&ipv6.octets());
                },
            };
        }

        let result = unsafe { transmute(result) };
        // println!("IpAddr {:#?} => {:#?}", self, result);

        Ok(IpAddrBytes(result))
    }
}