use std::ffi::CString;
use std::fmt::{Display, Formatter};
use std::slice;
use crate::community;

impl Display for community {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("community");

        debug.field("refcnt", &self.refcnt);
        debug.field("size", &self.size);
        if self.val.is_null() {
            debug.field("val", &self.val);
        } else {
            let slice = unsafe {
                slice::from_raw_parts(self.val, self.size as usize)
            };
            debug.field("val", &slice);
        }
        if self.str_.is_null() {
            debug.field("str_", &self.str_);
        } else {
            let str = unsafe {
                &CString::from_raw(self.str_)
            };
            debug.field("str_",  str);
        }

        debug.finish()
    }
}