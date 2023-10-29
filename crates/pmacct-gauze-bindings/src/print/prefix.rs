use std::fmt::{Debug, Formatter};
use std::{mem, slice};
use crate::{prefix, prefix__bindgen_ty_1, u_char};
use libc::{AF_INET, AF_INET6, c_int};

impl Debug for prefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("prefix");

        debug.field("family", &self.family)
            .field("prefixlen", &self.prefixlen);

        unsafe {
            match self.family as c_int {
                AF_INET => {
                    debug.field("u.prefix4", &self.u.prefix4);
                }
                AF_INET6 => {
                    debug.field("u.prefix6", &self.u.prefix6);
                }
                _ => {
                    let ptr = &self.u.prefix as *const u_char;
                    let union_size = mem::size_of::<prefix__bindgen_ty_1>();
                    let slice = slice::from_raw_parts(ptr, union_size);
                    debug.field("u.prefix_u8", &format!("{:?}", slice));
                }
            }
        }

        debug.finish()
    }
}