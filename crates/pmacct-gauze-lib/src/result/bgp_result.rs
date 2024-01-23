use crate::capi::bgp::ParsedBgp;
use crate::result::cresult::CResult;
use crate::result::ParseError;

pub type BgpResult = CResult<ParsedBgp, BgpParseError>;
pub type BmpBgpResult = CResult<ParsedBgp, ParseError>;

#[repr(C)]
#[derive(Debug)]
pub enum BgpParseError {
    WrongBgpMessageType,
}