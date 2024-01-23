use netgauze_bgp_pkt::community::{ExtendedCommunity, LargeCommunity};
use netgauze_parse_utils::WritablePdu;
use pmacct_gauze_bindings::{ecommunity_val, lcommunity_val, ECOMMUNITY_SIZE, LCOMMUNITY_SIZE};
use std::io::BufWriter;
use std::mem::transmute;

pub trait ExtendLargeCommunity {
    fn to_lcommunity_val(&self) -> lcommunity_val;
}

impl ExtendLargeCommunity for LargeCommunity {
    fn to_lcommunity_val(&self) -> lcommunity_val {
        let mut tmp = [0u8; LCOMMUNITY_SIZE as usize];
        {
            let mut writer = BufWriter::new(tmp.as_mut_slice());
            if let Err(_) = self.write(&mut writer) {
                drop(writer);
                tmp = [0u8; LCOMMUNITY_SIZE as usize]; // TODO error
            }
        }

        unsafe {
            lcommunity_val {
                val: transmute(tmp),
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
            let mut writer = BufWriter::new(tmp.as_mut_slice());
            if let Err(_) = self.write(&mut writer) {
                drop(writer);
                tmp = [0u8; ECOMMUNITY_SIZE as usize]; // TODO error
            }
        }

        unsafe {
            ecommunity_val {
                val: transmute(tmp),
            }
        }
    }
}
