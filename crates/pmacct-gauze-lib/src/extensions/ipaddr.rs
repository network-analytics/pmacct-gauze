use std::mem::transmute;
use std::net::IpAddr;
use netgauze_bgp_pkt::nlri::Ipv4UnicastAddress;
use netgauze_bgp_pkt::wire::serializer::IpAddrWritingError;
use pmacct_gauze_bindings::{AFI_IP, bgp_afi2family, in_addr, prefix, prefix__bindgen_ty_1, u_char};
use std::os::raw::c_int;

#[repr(transparent)]
#[derive(Default)]
pub struct IpAddrBytes(pub [u32; 4]);

impl IpAddrBytes {
    pub fn ipv4_u32(&self) -> u32 {
        self.0[3]
    }
}

pub trait ExtendIpAddr {
    fn to_bytes(&self) -> Result<IpAddrBytes, IpAddrWritingError>;
}

impl ExtendIpAddr for IpAddr {
    fn to_bytes(&self) -> Result<IpAddrBytes, IpAddrWritingError> {
        let mut result = [0u8; 16];
        {
            // TODO use to_bits
            match self {
                IpAddr::V4(ipv4) => {
                    result[12..].copy_from_slice(&ipv4.octets());
                }
                IpAddr::V6(ipv6) => {
                    result.copy_from_slice(&ipv6.octets());
                }
            };
        }

        let result = unsafe { transmute(result) };
        // println!("IpAddr {:#?} => {:#?}", self, result);

        Ok(IpAddrBytes(result))
    }
}

#[repr(transparent)]
pub struct CPrefix(pub prefix);

impl TryFrom<&Ipv4UnicastAddress> for CPrefix {
    type Error = IpAddrWritingError;
    fn try_from(value: &Ipv4UnicastAddress) -> Result<Self, Self::Error> {
        let pfx = prefix {
            family: unsafe { bgp_afi2family(AFI_IP as c_int) } as u_char,
            prefixlen: value.network().address().prefix_len(),
            __bindgen_padding_0: 0,
            u: prefix__bindgen_ty_1 {
                prefix4: in_addr {
                    s_addr: IpAddr::V4(value.network().address().addr()).to_bytes()?.ipv4_u32(),
                }
            },
        };

        Ok(Self(pfx))
    }
}