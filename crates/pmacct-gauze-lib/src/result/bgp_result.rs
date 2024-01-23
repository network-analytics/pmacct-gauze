use crate::c_api::ProcessPacket;
use crate::result::cresult::CResult;
use crate::result::ParseError;
use crate::slice::CSlice;

pub type BgpResult = CResult<ParsedBgp, BgpParseError>;
pub type BmpBgpResult = CResult<ParsedBgp, ParseError>;

#[repr(C)]
#[derive(Debug)]
pub enum BgpParseError {
    WrongBgpMessageType,
}

#[repr(C)]
#[derive(Debug)]
pub struct ParsedBgp {
    pub packets: CSlice<ProcessPacket>,
    pub update_count: usize,
}
