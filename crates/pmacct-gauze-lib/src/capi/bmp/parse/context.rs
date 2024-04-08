use std::collections::HashMap;

use netgauze_bgp_pkt::wire::deserializer::BgpParsingContext;
use netgauze_bmp_pkt::PeerKey;

use crate::{free_rust_raw_box, make_default};
use crate::capi::bmp::BmpMessageValueOpaque;
use crate::extensions::bmp_message::ExtendBmpMessage;

#[derive(Default)]
pub struct BmpParsingContext(HashMap<PeerKey, BgpParsingContext>);

make_default!(BmpParsingContext);

free_rust_raw_box!(BmpParsingContext);

impl AsMut<HashMap<PeerKey, BgpParsingContext>> for BmpParsingContext {
    fn as_mut(&mut self) -> &mut HashMap<PeerKey, BgpParsingContext> {
        &mut self.0
    }
}

impl AsRef<HashMap<PeerKey, BgpParsingContext>> for BmpParsingContext {
    fn as_ref(&self) -> &HashMap<PeerKey, BgpParsingContext> { &self.0 }
}


impl BmpParsingContext {
    pub fn peer_count(&self) -> usize {
        self.as_ref().len()
    }
    pub fn add_peer(&mut self, peer_key: PeerKey, parsing_context: BgpParsingContext) {
        let inner = self.as_mut();

        inner.insert(peer_key, parsing_context);
    }

    pub fn add_default_peer(&mut self, peer_key: PeerKey) {
        self.add_peer(peer_key, BgpParsingContext::default())
    }

    pub fn delete_peer(&mut self, peer_key: &PeerKey) {
        let inner = self.as_mut();

        inner.remove(peer_key);
    }

    pub fn get_peer(&mut self, peer_key: &PeerKey) -> Option<&mut BgpParsingContext> {
        let inner = self.as_mut();

        inner.get_mut(&peer_key)
    }
}

#[no_mangle]
pub extern "C" fn netgauze_bmp_parsing_context_add_default(
    bmp_parsing_context: *mut BmpParsingContext,
    bmp_message_value_opaque: *const BmpMessageValueOpaque,
) {
    let bmp_parsing_context = unsafe { bmp_parsing_context.as_mut().unwrap() };
    let bmp_message_value = unsafe { bmp_message_value_opaque.as_ref().unwrap() };
    let peer_header = bmp_message_value.value().get_peer_header().unwrap();

    let key = PeerKey::from_peer_header(peer_header);
    bmp_parsing_context.add_peer(key, Default::default());
}

#[no_mangle]
pub extern "C" fn netgauze_bmp_parsing_context_delete(
    bmp_parsing_context: *mut BmpParsingContext,
    bmp_message_value_opaque: *const BmpMessageValueOpaque,
) {
    let bmp_parsing_context = unsafe { bmp_parsing_context.as_mut().unwrap() };
    let bmp_message_value = unsafe { bmp_message_value_opaque.as_ref().unwrap() };
    let peer_header = bmp_message_value.value().get_peer_header().unwrap();

    let key = PeerKey::from_peer_header(peer_header);
    bmp_parsing_context.delete_peer(&key);
}