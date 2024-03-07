use netgauze_bgp_pkt::nlri::RouteDistinguisher;
use netgauze_bgp_pkt::wire::serializer::nlri::RouteDistinguisherWritingError;
use netgauze_parse_utils::WritablePdu;
use pmacct_gauze_bindings::{
    bgp_rd_origin_set, rd_t, RD_ORIGIN_BGP, RD_ORIGIN_BMP, RD_ORIGIN_FLOW, RD_ORIGIN_FUNC_TYPE_MAX,
    RD_ORIGIN_MAP, RD_ORIGIN_MASK, RD_ORIGIN_UNKNOWN,
};
use std::io::BufWriter;

#[repr(transparent)]
#[derive(Default)]
pub struct RouteDistinguisherBytes(pub [u8; 8]);

pub trait ExtendRouteDistinguisher {
    fn to_bytes(&self) -> Result<RouteDistinguisherBytes, RouteDistinguisherWritingError>;
    fn set_pmacct_rd_origin(self, origin: RdOriginType) -> RouteDistinguisher;
}

#[repr(u32)]
pub enum RdOriginType {
    Unknown = RD_ORIGIN_UNKNOWN,
    Mask = RD_ORIGIN_MASK,
    FuncTypeMax = RD_ORIGIN_FUNC_TYPE_MAX,
    BGP = RD_ORIGIN_BGP,
    BMP = RD_ORIGIN_BMP,
    FLOW = RD_ORIGIN_FLOW,
    MAP = RD_ORIGIN_MAP,
}

impl ExtendRouteDistinguisher for RouteDistinguisher {
    fn to_bytes(&self) -> Result<RouteDistinguisherBytes, RouteDistinguisherWritingError> {
        let mut result = [0u8; 8];
        {
            let mut writer = BufWriter::new(&mut result[..]);
            self.write(&mut writer)?;
        }

        Ok(RouteDistinguisherBytes(result))
    }

    fn set_pmacct_rd_origin(self, origin: RdOriginType) -> RouteDistinguisher {
        let mut new_rd: rd_t = self.into();
        new_rd.set_pmacct_rd_origin(origin);

        new_rd.into()
    }
}

pub trait ExtendRdT {
    fn set_pmacct_rd_origin(&mut self, origin: RdOriginType);
}

impl ExtendRdT for rd_t {
    fn set_pmacct_rd_origin(&mut self, origin: RdOriginType) {
        unsafe {
            bgp_rd_origin_set(self as *mut rd_t, origin as u16);
        }
    }
}
