use crate::convert::TryConvertInto;
use crate::{cap_per_af, cap_per_af_u16};
use netgauze_iana::address_family::AddressType;
use std::cmp::max;

#[repr(transparent)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct AddressTypeNotSupported(pub AddressType);

pub trait PerAddressTypeCapability<T> {
    fn from_iter<I>(iterator: I) -> (Self, Vec<AddressTypeNotSupported>)
    where
        I: IntoIterator<Item = (AddressType, T)>,
        Self: Sized,
    {
        let mut ok: Self = unsafe { std::mem::zeroed() };
        let mut errs = Vec::new();

        for (address_type, value) in iterator {
            match ok.set_value(address_type, value) {
                Ok(_) => {}
                Err(err) => {
                    errs.push(err);
                    continue;
                }
            };
        }

        (ok, errs)
    }

    fn set_value(
        &mut self,
        address_type: AddressType,
        value: T,
    ) -> Result<(), AddressTypeNotSupported>;
}

impl PerAddressTypeCapability<u8> for cap_per_af {
    fn set_value(
        &mut self,
        address_type: AddressType,
        value: u8,
    ) -> Result<(), AddressTypeNotSupported> {
        let (afi, safi) = match address_type.try_convert_to() {
            Ok((afi, safi)) => (afi, safi),
            Err(_) => {
                return Err(AddressTypeNotSupported(address_type));
            }
        };

        // We know afi < AFI_MAX and safi < SAFI_MAX thanks to try_convert_to
        self.cap[afi as usize][safi as usize] = value;
        self.afi_max = max(self.afi_max, afi);
        self.safi_max = max(self.safi_max, safi);

        Ok(())
    }
}

impl PerAddressTypeCapability<u16> for cap_per_af_u16 {
    fn set_value(
        &mut self,
        address_type: AddressType,
        value: u16,
    ) -> Result<(), AddressTypeNotSupported> {
        let (afi, safi) = match address_type.try_convert_to() {
            Ok((afi, safi)) => (afi, safi),
            Err(_) => {
                return Err(AddressTypeNotSupported(address_type));
            }
        };

        // We know afi < AFI_MAX and safi < SAFI_MAX thanks to try_convert_to
        self.cap[afi as usize][safi as usize] = value;
        self.afi_max = max(self.afi_max, afi);
        self.safi_max = max(self.safi_max, safi);

        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use crate::utils::cap_per_af::{AddressTypeNotSupported, PerAddressTypeCapability};
    use crate::{cap_per_af, AFI_IP, AFI_IP6, SAFI_MPLS_VPN, SAFI_UNICAST};
    use netgauze_bgp_pkt::capabilities::AddPathAddressFamily;
    use netgauze_iana::address_family::AddressType::{
        BgpLsVpn, Ipv4MplsLabeledVpn, Ipv4Unicast, Ipv6MplsLabeledVpn, Ipv6Unicast,
    };

    #[test]
    pub fn test_address_type_conversion() {
        let add_path = [
            AddPathAddressFamily::new(Ipv4Unicast, false, false), // 0
            AddPathAddressFamily::new(Ipv4MplsLabeledVpn, false, true), // 1
            AddPathAddressFamily::new(Ipv6Unicast, true, false),  // 2
            AddPathAddressFamily::new(Ipv6MplsLabeledVpn, true, true), // 3
            AddPathAddressFamily::new(BgpLsVpn, true, true),      // Error
        ];

        let iter = add_path.iter().map(|add_path_address_family| {
            (
                add_path_address_family.address_type(),
                match (
                    add_path_address_family.send(),
                    add_path_address_family.receive(),
                ) {
                    (false, false) => 0,
                    (false, true) => 1,
                    (true, false) => 2,
                    (true, true) => 3,
                },
            )
        });

        let (ok, err) = cap_per_af::from_iter(iter);
        assert_eq!(ok.afi_max, AFI_IP6 as u16);
        assert_eq!(ok.safi_max, SAFI_MPLS_VPN as u8);
        assert_eq!(ok.cap[AFI_IP as usize][SAFI_UNICAST as usize], 0);
        assert_eq!(ok.cap[AFI_IP as usize][SAFI_MPLS_VPN as usize], 1);
        assert_eq!(ok.cap[AFI_IP6 as usize][SAFI_UNICAST as usize], 2);
        assert_eq!(ok.cap[AFI_IP6 as usize][SAFI_MPLS_VPN as usize], 3);
        assert_eq!(err.len(), 1);
        assert_eq!(err[0], AddressTypeNotSupported(BgpLsVpn));
    }
}
