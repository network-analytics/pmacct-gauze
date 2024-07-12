use std::ptr::null_mut;

use netgauze_bgp_pkt::wire::deserializer::BgpParsingContext;

use pmacct_gauze_bindings::bgp_peer;

use crate::{free_rust_raw_box, make_default};
use crate::context_cache::ContextCache;
use crate::opaque::Opaque;

pub type BgpContextCacheKey = *mut bgp_peer;
pub type BgpContextCache = ContextCache<BgpContextCacheKey, BgpParsingContext>;
free_rust_raw_box!(Opaque<BgpParsingContext>, Opaque_BgpParsingContext);
make_default!(Opaque<BgpParsingContext>, Opaque_BgpParsingContext);

free_rust_raw_box!(Opaque<BgpContextCache>, Opaque_BgpContextCache);
make_default!(Opaque<BgpContextCache>, Opaque_BgpContextCache);

#[no_mangle]
pub extern "C" fn netgauze_bgp_context_cache_set(
    opaque_context_cache: *mut Opaque<BgpContextCache>,
    context_cache_key: BgpContextCacheKey,
    opaque_bgp_parsing_context: *mut Opaque<BgpParsingContext>,
) -> *mut Opaque<BgpParsingContext> {
    let context_cache = unsafe { opaque_context_cache.as_mut().unwrap().as_mut() };
    let bgp_parsing_context = unsafe { Box::from_raw(opaque_bgp_parsing_context) };
    let value = Opaque::value(*bgp_parsing_context);

    context_cache.insert(context_cache_key, value);

    netgauze_bgp_context_cache_get(opaque_context_cache, context_cache_key)
}

#[allow(clippy::not_unsafe_ptr_arg_deref)] // The pointer is not null by contract
#[no_mangle]
pub extern "C" fn netgauze_bgp_context_cache_get(
    opaque_context_cache: *mut Opaque<BgpContextCache>,
    context_cache_key: BgpContextCacheKey,
) -> *mut Opaque<BgpParsingContext> {
    let context_cache = unsafe { opaque_context_cache.as_mut().unwrap().as_mut() };

    if let Some(parsing_context) = context_cache.get_mut(&context_cache_key) {
        parsing_context as *mut BgpParsingContext as *mut Opaque<BgpParsingContext>
    } else {
        null_mut()
    }
}

#[allow(clippy::not_unsafe_ptr_arg_deref)] // The pointer is not null by contract
#[no_mangle]
pub extern "C" fn netgauze_bgp_context_cache_delete(
    opaque_context_cache: *mut Opaque<BgpContextCache>,
    context_cache_key: BgpContextCacheKey,
) {
    let context_cache = unsafe { opaque_context_cache.as_mut().unwrap().as_mut() };
    let _ = context_cache.remove(&context_cache_key);
}
