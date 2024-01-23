use crate::result::bgp_result::BgpParseError;
use crate::result::bmp_result::BmpParseError;

pub mod bgp_result;
pub mod bmp_result;
pub mod cresult;

#[repr(C)]
#[derive(Debug)]
pub enum ParseError {
    ParseErrorBgp(BgpParseError),
    ParseErrorBmp(BmpParseError),
}
