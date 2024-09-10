use std::error::Error;
use std::fmt::{Debug, Display, Formatter};

use netgauze_bgp_pkt::iana::BgpMessageType;

use pmacct_gauze_bindings::{
    aspath, aspath_free, aspath_reconcile_as4, BGP_NLRI_UPDATE, BGP_NLRI_WITHDRAW,
};

use crate::cresult::CResult;

pub mod open;
pub mod parse;
pub mod update;

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

/// Rewrite of [aspath_reconcile_as4]
/// # Safety
/// Both [*mut aspath] need to have been allocated by pmacct using
/// - [pmacct_gauze_bindings::aspath_make_empty]
/// - [pmacct_gauze_bindings::aspath_dup]
pub unsafe fn reconcile_as24path(as_path: *mut aspath, as4_path: *mut aspath) -> *mut aspath {
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

    as4_path
}
