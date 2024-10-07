use std::io::BufWriter;
use std::mem::transmute;
use std::os::raw::c_char;

use netgauze_bgp_pkt::community::{ExtendedCommunity, LargeCommunity};
use netgauze_parse_utils::WritablePdu;

use pmacct_gauze_bindings::{ecommunity_val, lcommunity_val, ECOMMUNITY_SIZE, LCOMMUNITY_SIZE};

pub trait ExtendLargeCommunity {
    fn to_lcommunity_val(&self) -> lcommunity_val;
}

impl ExtendLargeCommunity for LargeCommunity {
    fn to_lcommunity_val(&self) -> lcommunity_val {
        let mut tmp = [0u8; LCOMMUNITY_SIZE as usize];
        {
            // TODO make a method for LargeCommunity to_bytes
            let mut writer = BufWriter::new(tmp.as_mut_slice());
            if self.write(&mut writer).is_err() {
                drop(writer);
                tmp = [0u8; LCOMMUNITY_SIZE as usize]; // TODO error
            }
        }

        unsafe {
            lcommunity_val {
                val: transmute::<[u8; 12], [c_char; 12]>(tmp),
            }
        }
    }
}

pub trait ExtendExtendedCommunity {
    fn to_ecommunity_val(&self) -> ecommunity_val;
}

impl ExtendExtendedCommunity for ExtendedCommunity {
    fn to_ecommunity_val(&self) -> ecommunity_val {
        let mut tmp = [0u8; ECOMMUNITY_SIZE as usize];
        {
            // TODO make a method for ExtendedCommunity to_bytes
            let mut writer = BufWriter::new(tmp.as_mut_slice());
            if self.write(&mut writer).is_err() {
                drop(writer);
                tmp = [0u8; ECOMMUNITY_SIZE as usize]; // TODO error
            }
        }

        unsafe {
            ecommunity_val {
                val: transmute::<[u8; 8], [c_char; 8]>(tmp),
            }
        }
    }
}
