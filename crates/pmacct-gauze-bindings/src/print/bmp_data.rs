use crate::bmp_data;
use std::fmt::{Debug, Formatter};

impl Debug for bmp_data {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("bmp_data");
        debug.field("family", &self.family);
        debug.field("peer_ip", &self.peer_ip);
        debug.field("bgp_id", &self.bgp_id);
        debug.field("peer_asn", &self.peer_asn);
        debug.field("chars", &self.chars);
        debug.field("tstamp", &self.tstamp);
        debug.field("tstamp_arrival", &self.tstamp_arrival);
        debug.finish()
    }
}