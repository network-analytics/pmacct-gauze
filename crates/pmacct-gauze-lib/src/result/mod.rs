use crate::result::bgp_result::BgpParseError;
use crate::result::bmp_result::BmpParseError;

pub mod cresult;
pub mod bmp_result;
pub mod bgp_result;

#[repr(C)]
#[derive(Debug)]
pub enum ParseError {
    ParseErrorBgp(BgpParseError),
    ParseErrorBmp(BmpParseError)
}