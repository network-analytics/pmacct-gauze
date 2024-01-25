use netgauze_bmp_pkt::iana::PeerTerminationCode;
use netgauze_bmp_pkt::{InitiationInformation, TerminationInformation};
use std::ffi::c_void;

pub trait TlvExtension {
    fn get_value_ptr(&self) -> *mut c_void;
}

impl TlvExtension for InitiationInformation {
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

impl TlvExtension for TerminationInformation {
    fn get_value_ptr(&self) -> *mut c_void {
        let ptr = match self {
            TerminationInformation::String(str) => str.as_ptr(),
            TerminationInformation::Reason(value) => {
                value as *const PeerTerminationCode as *const u8
            }
            TerminationInformation::Experimental65531(value) => value.as_ptr(),
            TerminationInformation::Experimental65532(value) => value.as_ptr(),
            TerminationInformation::Experimental65533(value) => value.as_ptr(),
            TerminationInformation::Experimental65534(value) => value.as_ptr(),
        };

        ptr as *mut c_void
    }
}
