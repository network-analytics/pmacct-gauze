use crate::bgp_attr;
use std::fmt::{Debug, Formatter};

impl Debug for bgp_attr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("bgp_attr");

        debug.field("aspath", &self.aspath);
        debug.field("community", &self.community);
        debug.field("ecommunity", &self.ecommunity);
        debug.field("lcommunity", &self.lcommunity);
        debug.field("refcnt", &self.refcnt);
        debug.field("rpki_maxlen", &self.rpki_maxlen);
        debug.field("nexthop", &self.nexthop);
        debug.field("mp_nexthop", &self.mp_nexthop);
        debug.field("med", &self.med);
        debug.field("local_pref", &self.local_pref);
        debug.field("origin", &self.origin);
        debug.field("bitmap", &self.bitmap);

        debug.finish()
    }
}
