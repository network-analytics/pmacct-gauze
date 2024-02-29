use crate::cresult::CResult;
use netgauze_bgp_pkt::iana::BgpMessageType;
use netgauze_bgp_pkt::update::BgpUpdateMessage;
use netgauze_bgp_pkt::BgpMessage;
use pmacct_gauze_bindings::{
    aspath, aspath_free, aspath_reconcile_as4, BGP_NLRI_UPDATE, BGP_NLRI_WITHDRAW,
};
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

pub mod open;
pub mod parse;
pub mod update;

pub struct BgpMessageOpaque(BgpMessage);

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct WrongBgpMessageTypeError(pub u8);

impl From<BgpMessageType> for WrongBgpMessageTypeError {
    fn from(value: BgpMessageType) -> Self {
        Self(value.into())
    }
}

impl Display for WrongBgpMessageTypeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for WrongBgpMessageTypeError {}

impl<T> From<WrongBgpMessageTypeError> for CResult<T, WrongBgpMessageTypeError> {
    fn from(value: WrongBgpMessageTypeError) -> Self {
        Self::Err(value)
    }
}

#[repr(transparent)]
struct DebugUpdateType(u32);

impl Debug for DebugUpdateType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({})",
            match self.0 {
                BGP_NLRI_UPDATE => "BGP_NLRI_UPDATE",
                BGP_NLRI_WITHDRAW => "BGP_NLRI_WITHDRAW",
                _ => "BGP_NLRI_UNDEFINED",
            },
            self.0
        )
    }
}

pub fn reconcile_as24path(as_path: *mut aspath, as4_path: *mut aspath) -> *mut aspath {
    if !as_path.is_null() && !as4_path.is_null() {
        let reconciled = unsafe { aspath_reconcile_as4(as_path, as4_path) };
        if !reconciled.is_null() {
            unsafe {
                aspath_free(as_path);
                aspath_free(as4_path);
            }

            return reconciled;
        }
    }

    if !as_path.is_null() {
        return as_path;
    }

    return as4_path;
}
