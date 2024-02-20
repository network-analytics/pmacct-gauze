use crate::result::bgp_result::BgpUpdateError;
use crate::result::bmp_result::BmpParseError;

pub mod bgp_result;
pub mod bmp_result;
pub mod cresult;

#[repr(C)]
#[derive(Debug)]
pub enum ParseError {
    ParseErrorBgp(BgpUpdateError),
    ParseErrorBmp(BmpParseError),
}
