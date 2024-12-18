use crate::extensions::add_path::AddPathCapabilityValue::{Both, ReceiveOnly, SendOnly, Unset};
use netgauze_bgp_pkt::capabilities::AddPathAddressFamily;
use netgauze_iana::address_family::AddressType;
use pmacct_gauze_bindings::convert::TryConvertInto;
use pmacct_gauze_bindings::{afi_t, cap_per_af, safi_t};
use std::collections::HashMap;

#[repr(u8)]
pub enum AddPathCapabilityValue {
    Unset = 0,
    ReceiveOnly = 1,
    SendOnly = 2,
    Both = 3,
}

impl From<&AddPathAddressFamily> for AddPathCapabilityValue {
    fn from(value: &AddPathAddressFamily) -> Self {
        Self::from_bool(value.send(), value.receive())
    }
}
impl AddPathCapabilityValue {
    pub fn from_bool(send: bool, receive: bool) -> Self {
        match (send, receive) {
            (true, true) => Both,
            (true, false) => SendOnly,
            (false, true) => ReceiveOnly,
            (false, false) => Unset,
        }
    }
}

pub trait AddPathCapability {
    fn get_receive_map(&self) -> Result<HashMap<AddressType, bool>, (afi_t, safi_t)>;
    fn get_send_map(&self) -> Result<HashMap<AddressType, bool>, (afi_t, safi_t)>;
}

impl AddPathCapability for cap_per_af {
    fn get_receive_map(&self) -> Result<HashMap<AddressType, bool>, (afi_t, safi_t)> {
        let mut result = HashMap::new();

        for afi in 0..self.afi_max {
            for safi in 0..self.safi_max {
                let cap_value = self.cap[afi as usize][safi as usize];
                if cap_value == ReceiveOnly as u8 || cap_value == Both as u8 {
                    let (ng_afi, ng_safi) = (afi.try_convert_to(), safi.try_convert_to());
                    if ng_afi.is_err() || ng_safi.is_err() {
                        return Err((afi, safi));
                    }

                    let address_type = if let Ok(address_type) =
                        AddressType::from_afi_safi(ng_afi.unwrap(), ng_safi.unwrap())
                    {
                        address_type
                    } else {
                        return Err((afi, safi));
                    };

                    result.insert(address_type, true);
                }
            }
        }

        Ok(result)
    }

    fn get_send_map(&self) -> Result<HashMap<AddressType, bool>, (afi_t, safi_t)> {
        let mut result = HashMap::new();

        for afi in 0..self.afi_max {
            for safi in 0..self.safi_max {
                let cap_value = self.cap[afi as usize][safi as usize];
                if cap_value == SendOnly as u8 || cap_value == Both as u8 {
                    let (ng_afi, ng_safi) = (afi.try_convert_to(), safi.try_convert_to());
                    if ng_afi.is_err() || ng_safi.is_err() {
                        return Err((afi, safi));
                    }

                    let address_type = if let Ok(address_type) =
                        AddressType::from_afi_safi(ng_afi.unwrap(), ng_safi.unwrap())
                    {
                        address_type
                    } else {
                        return Err((afi, safi));
                    };

                    result.insert(address_type, true);
                }
            }
        }

        Ok(result)
    }
}
