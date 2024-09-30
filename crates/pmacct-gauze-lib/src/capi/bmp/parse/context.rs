use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::ptr::null_mut;

use netgauze_bmp_pkt::wire::deserializer::BmpParsingContext;
use netgauze_bmp_pkt::{BmpMessageValue, PeerKey};

use pmacct_gauze_bindings::bmp_peer;

use crate::extensions::bmp_message::ExtendBmpMessage;
use crate::extensions::context::ExtendBmpParsingContext;
use crate::opaque::Opaque;
use crate::{free_rust_raw_box, make_default};

make_default!(Opaque<BmpParsingContext>, Opaque_BmpParsingContext);

free_rust_raw_box!(Opaque<BmpParsingContext>, Opaque_BmpParsingContext);

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

pub type ContextCacheKey = *mut bmp_peer;

free_rust_raw_box!(Opaque<ContextCache>, Opaque_ContextCache);
make_default!(Opaque<ContextCache>, Opaque_ContextCache);

#[derive(Default, Debug, Clone)]
pub struct ContextCache {
    map: HashMap<ContextCacheKey, BmpParsingContext>,
}

impl Deref for ContextCache {
    type Target = HashMap<ContextCacheKey, BmpParsingContext>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl DerefMut for ContextCache {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.map
    }
}

#[no_mangle]
pub extern "C" fn netgauze_context_cache_set(
    opaque_context_cache: *mut Opaque<ContextCache>,
    context_cache_key: ContextCacheKey,
    opaque_bmp_parsing_context: *mut Opaque<BmpParsingContext>,
) -> *mut Opaque<BmpParsingContext> {
    let context_cache = unsafe { opaque_context_cache.as_mut().unwrap().as_mut() };
    let bmp_parsing_context = unsafe { Box::from_raw(opaque_bmp_parsing_context) };
    let value = Opaque::value(*bmp_parsing_context);

    context_cache.insert(context_cache_key, value);

    netgauze_context_cache_get(opaque_context_cache, context_cache_key)
}

#[no_mangle]
pub extern "C" fn netgauze_context_cache_get(
    opaque_context_cache: *mut Opaque<ContextCache>,
    context_cache_key: ContextCacheKey,
) -> *mut Opaque<BmpParsingContext> {
    let context_cache = unsafe { opaque_context_cache.as_mut().unwrap().as_mut() };

    if let Some(parsing_context) = context_cache.get_mut(&context_cache_key) {
        parsing_context as *mut BmpParsingContext as *mut Opaque<BmpParsingContext>
    } else {
        null_mut()
    }
}

#[no_mangle]
pub extern "C" fn netgauze_context_cache_delete(
    opaque_context_cache: *mut Opaque<ContextCache>,
    context_cache_key: ContextCacheKey,
) {
    let context_cache = unsafe { opaque_context_cache.as_mut().unwrap().as_mut() };
    let _ = context_cache.remove(&context_cache_key);
}

#[cfg(test)]
mod test {
    use pmacct_gauze_bindings::bmp_peer;

    use crate::capi::bmp::parse::{
        netgauze_context_cache_set, netgauze_make_Opaque_BmpParsingContext,
        netgauze_make_Opaque_ContextCache,
    };

    #[test]
    fn test_leak() {
        let cache = netgauze_make_Opaque_ContextCache();
        let ctx = netgauze_make_Opaque_BmpParsingContext();
        let mut peer: bmp_peer = unsafe { std::mem::zeroed() };
        netgauze_context_cache_set(cache, &mut peer, ctx);
    }
}
