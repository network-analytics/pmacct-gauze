use netgauze_bgp_pkt::wire::deserializer::BgpParsingContext;
use netgauze_bmp_pkt::PeerKey;
use netgauze_bmp_pkt::wire::deserializer::BmpParsingContext;

pub trait ExtendBmpParsingContext {
    fn peer_count(&self) -> usize;
    fn add_peer(&mut self, peer_key: PeerKey, parsing_context: BgpParsingContext);

    fn add_default_peer(&mut self, peer_key: PeerKey);

    fn delete_peer(&mut self, peer_key: &PeerKey);

    fn get_peer(&mut self, peer_key: &PeerKey) -> Option<&mut BgpParsingContext>;
}

impl ExtendBmpParsingContext for BmpParsingContext {
    fn peer_count(&self) -> usize {
        self.0.len()
    }
    fn add_peer(&mut self, peer_key: PeerKey, parsing_context: BgpParsingContext) {
        let inner = &mut self.0;

        inner.insert(peer_key, parsing_context);
    }

    fn add_default_peer(&mut self, peer_key: PeerKey) {
        self.add_peer(peer_key, BgpParsingContext::default())
    }

    fn delete_peer(&mut self, peer_key: &PeerKey) {
        let inner = &mut self.0;

        inner.remove(peer_key);
    }

    fn get_peer(&mut self, peer_key: &PeerKey) -> Option<&mut BgpParsingContext> {
        let inner = &mut self.0;

        inner.get_mut(&peer_key)
    }
}
