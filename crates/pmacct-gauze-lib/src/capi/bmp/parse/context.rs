use std::ptr::null_mut;

use netgauze_bmp_pkt::wire::deserializer::BmpParsingContext;
use netgauze_bmp_pkt::{BmpMessageValue, PeerKey};

use pmacct_gauze_bindings::bmp_peer;

use crate::{free_rust_raw_box, make_default};
use crate::context_cache::ContextCache;
use crate::extensions::bmp_message::ExtendBmpMessage;
use crate::extensions::context::ExtendBmpParsingContext;
use crate::opaque::Opaque;

pub type BmpContextCacheKey = *mut bmp_peer;
pub type BmpContextCache = ContextCache<BmpContextCacheKey, BmpParsingContext>;

free_rust_raw_box!(Opaque<BmpContextCache>, Opaque_BmpContextCache);
make_default!(Opaque<BmpContextCache>, Opaque_BmpContextCache);

#[no_mangle]
pub extern "C" fn netgauze_bmp_context_cache_set(
    opaque_context_cache: *mut Opaque<BmpContextCache>,
    context_cache_key: BmpContextCacheKey,
    opaque_bmp_parsing_context: *mut Opaque<BmpParsingContext>,
) -> *mut Opaque<BmpParsingContext> {
    let context_cache = unsafe { opaque_context_cache.as_mut().unwrap().as_mut() };
    let bmp_parsing_context = unsafe { Box::from_raw(opaque_bmp_parsing_context) };
    let value = Opaque::value(*bmp_parsing_context);

    context_cache.insert(context_cache_key, value);

    netgauze_bmp_context_cache_get(opaque_context_cache, context_cache_key)
}

#[no_mangle]
pub extern "C" fn netgauze_bmp_context_cache_get(
    opaque_context_cache: *mut Opaque<BmpContextCache>,
    context_cache_key: BmpContextCacheKey,
) -> *mut Opaque<BmpParsingContext> {
    let context_cache = unsafe { opaque_context_cache.as_mut().unwrap().as_mut() };

    if let Some(parsing_context) = context_cache.get_mut(&context_cache_key) {
        parsing_context as *mut BmpParsingContext as *mut Opaque<BmpParsingContext>
    } else {
        null_mut()
    }
}

#[no_mangle]
pub extern "C" fn netgauze_bmp_context_cache_delete(
    opaque_context_cache: *mut Opaque<BmpContextCache>,
    context_cache_key: BmpContextCacheKey,
) {
    let context_cache = unsafe { opaque_context_cache.as_mut().unwrap().as_mut() };
    let _ = context_cache.remove(&context_cache_key);
}

make_default!(Opaque<BmpParsingContext>, Opaque_BmpParsingContext);
free_rust_raw_box!(Opaque<BmpParsingContext>, Opaque_BmpParsingContext);

#[allow(clippy::not_unsafe_ptr_arg_deref)] // The pointer is not null by contract
#[no_mangle]
pub extern "C" fn netgauze_bmp_parsing_context_add_default(
    bmp_parsing_context: *mut Opaque<BmpParsingContext>,
    bmp_message_value_opaque: *const Opaque<BmpMessageValue>,
) {
    let bmp_parsing_context = unsafe { bmp_parsing_context.as_mut().unwrap().as_mut() };
    let bmp_message_value = unsafe { bmp_message_value_opaque.as_ref().unwrap() };
    let peer_header = bmp_message_value.as_ref().get_peer_header().unwrap();

    let key = PeerKey::from_peer_header(peer_header);
    bmp_parsing_context.add_peer(key, Default::default());
}

#[allow(clippy::not_unsafe_ptr_arg_deref)] // The pointer is not null by contract
#[no_mangle]
pub extern "C" fn netgauze_bmp_parsing_context_delete(
    bmp_parsing_context: *mut Opaque<BmpParsingContext>,
    bmp_message_value_opaque: *const Opaque<BmpMessageValue>,
) {
    let bmp_parsing_context = unsafe { bmp_parsing_context.as_mut().unwrap().as_mut() };
    let bmp_message_value = unsafe { bmp_message_value_opaque.as_ref().unwrap() };
    let peer_header = bmp_message_value.as_ref().get_peer_header().unwrap();

    let key = PeerKey::from_peer_header(peer_header);
    bmp_parsing_context.delete_peer(&key);
}

#[cfg(test)]
mod test {
    use pmacct_gauze_bindings::bmp_peer;

    use crate::capi::bmp::parse::{netgauze_bmp_context_cache_set, netgauze_make_Opaque_BmpContextCache, netgauze_make_Opaque_BmpParsingContext};

    #[test]
    fn test_leak() {
        let cache = netgauze_make_Opaque_BmpContextCache();
        let ctx = netgauze_make_Opaque_BmpParsingContext();
        let mut peer: bmp_peer = unsafe { std::mem::zeroed() };

        netgauze_bmp_context_cache_set(cache, &mut peer, ctx);
    }
}