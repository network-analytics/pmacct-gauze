use crate::convert::TryConvertFrom;
use crate::{afi_t, safi_t, AFI_MAX, SAFI_MAX};
use netgauze_iana::address_family::{AddressFamily, SubsequentAddressFamily};

impl TryConvertFrom<afi_t> for AddressFamily {
    type Error = ();

    fn try_convert_from(value: afi_t) -> Result<Self, ()> {
        match AddressFamily::from_repr(value) {
            None => Err(()),
            Some(address_family) => Ok(address_family),
        }
    }
}

impl TryConvertFrom<AddressFamily> for afi_t {
    type Error = ();

    fn try_convert_from(value: AddressFamily) -> Result<Self, ()> {
        if (value as afi_t) < (AFI_MAX as afi_t) {
            Ok(value as afi_t)
        } else {
            Err(())
        }
    }
}

impl TryConvertFrom<safi_t> for SubsequentAddressFamily {
    type Error = ();

    fn try_convert_from(value: safi_t) -> Result<Self, ()> {
        match SubsequentAddressFamily::from_repr(value) {
            None => Err(()),
            Some(sub_address_family) => Ok(sub_address_family),
        }
    }
}

impl TryConvertFrom<SubsequentAddressFamily> for safi_t {
    type Error = ();

    fn try_convert_from(value: SubsequentAddressFamily) -> Result<Self, ()> {
        if (value as safi_t) < (SAFI_MAX as safi_t) {
            Ok(value as safi_t)
        } else {
            Err(())
        }
    }
}
