use std::io::BufWriter;
use netgauze_bgp_pkt::nlri::RouteDistinguisher;
use netgauze_bgp_pkt::wire::serializer::nlri::RouteDistinguisherWritingError;
use netgauze_parse_utils::WritablePdu;

#[repr(transparent)]
#[derive(Default)]
pub struct RouteDistinguisherBytes(pub [u8; 8]);

pub trait ExtendRd {
    fn to_bytes(&self) -> Result<RouteDistinguisherBytes, RouteDistinguisherWritingError>;
}

impl ExtendRd for RouteDistinguisher {
    fn to_bytes(&self) -> Result<RouteDistinguisherBytes, RouteDistinguisherWritingError> {

        let mut result = [0u8; 8];
        {
            let mut writer = BufWriter::new(&mut result[..]);
            self.write(&mut writer)?;
        }

        Ok(RouteDistinguisherBytes(result))
    }
}