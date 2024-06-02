use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::ptr::null_mut;

use netgauze_bmp_pkt::{BmpMessageValue, PeerKey};
use netgauze_bmp_pkt::wire::deserializer::BmpParsingContext;

use pmacct_gauze_bindings::bmp_peer;

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

pub type ContextCacheKey = *mut bmp_peer;

free_rust_raw_box!(Opaque<ContextCache>, Opaque_ContextCache);
make_default!(Opaque<ContextCache>, Opaque_ContextCache);

#[derive(Default, Debug, Clone)]
pub struct ContextCache {
    map: HashMap<ContextCacheKey, BmpParsingContext>,
}

impl Deref for ContextCache
{
    type Target = HashMap<ContextCacheKey, BmpParsingContext>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl DerefMut for ContextCache
{
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
    use std::ptr::null_mut;

    use pmacct_gauze_bindings::{bgp_peer, bgp_peer_buf, bgp_peer_stats, bgp_xconnect, bmp_peer, cap_per_af, host_addr, host_addr__bindgen_ty_1, host_mask, host_mask__bindgen_ty_1, in_addr, log_notification, sockaddr_storage};

    use crate::capi::bmp::parse::{netgauze_context_cache_set, netgauze_make_Opaque_BmpParsingContext, netgauze_make_Opaque_ContextCache};

    #[test]
    fn test_leak() {
        let cache = netgauze_make_Opaque_ContextCache();
        let ctx = netgauze_make_Opaque_BmpParsingContext();
        let mut peer = bmp_peer {
            self_: bgp_peer {
                idx: 0,
                fd: 0,
                lock: 0,
                type_: 0,
                status: 0,
                version: 0,
                myas: 0,
                as_: 0,
                ht: 0,
                last_keepalive: 0,
                id: Default::default(),
                addr: Default::default(),
                addr_str: [0; 46],
                tcp_port: 0,
                cap_mp: 0,
                cap_4as: null_mut(),
                cap_add_paths: cap_per_af {
                    cap: [[0; 129]; 3],
                    afi_max: 0,
                    safi_max: 0,
                },
                msglen: 0,
                stats: bgp_peer_stats {
                    packets: 0,
                    packet_bytes: 0,
                    msg_bytes: 0,
                    msg_errors: 0,
                    last_check: 0,
                },
                buf: bgp_peer_buf {
                    base: null_mut(),
                    tot_len: 0,
                    cur_len: 0,
                    exp_len: 0,
                },
                log: null_mut(),
                bmp_se: null_mut(),
                xc: bgp_xconnect {
                    id: 0,
                    dst: sockaddr_storage {
                        ss_family: 0,
                        __ss_padding: [0; 118],
                        __ss_align: 0,
                    },
                    dst_len: 0,
                    src: sockaddr_storage {
                        ss_family: 0,
                        __ss_padding: [0; 118],
                        __ss_align: 0,
                    },
                    src_len: 0,
                    src_addr: host_addr {
                        family: 0,
                        address: host_addr__bindgen_ty_1 {
                            ipv4: in_addr {
                                s_addr: 0,
                            }
                        },
                    },
                    src_mask: host_mask {
                        family: 0,
                        len: 0,
                        mask: host_mask__bindgen_ty_1 { m4: 0 },
                    },
                },
                xbuf: bgp_peer_buf {
                    base: null_mut(),
                    tot_len: 0,
                    cur_len: 0,
                    exp_len: 0,
                },
                xconnect_fd: 0,
                parsed_proxy_header: 0,
            },
            bgp_peers_v4: null_mut(),
            bgp_peers_v6: null_mut(),
            missing_peer_up: log_notification {
                stamp: 0,
                knob: 0,
                timeout: 0,
            },
        };

        netgauze_context_cache_set(cache, &mut peer, ctx);
    }
}