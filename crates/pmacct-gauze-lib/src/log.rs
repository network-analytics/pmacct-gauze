use libc::{LOG_ALERT, LOG_CRIT, LOG_DEBUG, LOG_EMERG, LOG_ERR, LOG_INFO, LOG_NOTICE, LOG_WARNING};
use pmacct_gauze_bindings::Log;
use std::ffi::{c_char, c_short, CString};

#[repr(u8)]
pub enum LogPriority {
    Emergency = LOG_EMERG as u8,
    Alert = LOG_ALERT as u8,
    Crititical = LOG_CRIT as u8,
    Error = LOG_ERR as u8,
    Warning = LOG_WARNING as u8,
    Notice = LOG_NOTICE as u8,
    Informational = LOG_INFO as u8,
    Debug = LOG_DEBUG as u8,
}

pub fn pmacct_log(prio: LogPriority, message: &str) {
    unsafe {
        if let Ok(str) = CString::new(message) {
            Log(prio as c_short, str.as_ptr() as *mut c_char);
        } else {
            eprintln!("[pmacct-gauze] internal error, message {:?} cannot be safely converted to null-terminated string", message);
        }
    }
}
