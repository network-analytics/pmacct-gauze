use std::ffi::c_void;
use netgauze_bmp_pkt::InitiationInformation;

pub trait InitInfoExtend {

    fn get_value_ptr(&self) -> *mut c_void;
}

impl InitInfoExtend for InitiationInformation {
    fn get_value_ptr(&self) -> *mut c_void {
        let ptr = match self {
            InitiationInformation::String(str) => str.as_ptr(),
            InitiationInformation::SystemDescription(str) => str.as_ptr(),
            InitiationInformation::SystemName(str) => str.as_ptr(),
            InitiationInformation::VrfTableName(str) => str.as_ptr(),
            InitiationInformation::AdminLabel(str) => str.as_ptr(),
            InitiationInformation::Experimental65531(bytes) => bytes.as_ptr(),
            InitiationInformation::Experimental65532(bytes) => bytes.as_ptr(),
            InitiationInformation::Experimental65533(bytes) => bytes.as_ptr(),
            InitiationInformation::Experimental65534(bytes) => bytes.as_ptr(),
        };

        ptr as *mut c_void
    }
}