use netgauze_bmp_pkt::{BmpMessageValue, PeerKey};
use netgauze_bmp_pkt::wire::deserializer::BmpParsingContext;

use crate::{free_rust_raw_box, make_default};
use crate::extensions::bmp_message::ExtendBmpMessage;
use crate::extensions::context::ExtendBmpParsingContext;
use crate::opaque::Opaque;

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
