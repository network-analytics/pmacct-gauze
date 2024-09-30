use crate::{timeval, DefaultZeroed};
use chrono::{DateTime, TimeZone, Utc};

impl<T: TimeZone> From<&DateTime<T>> for timeval {
    fn from(value: &DateTime<T>) -> Self {
        Self {
            tv_sec: value.timestamp(),
            tv_usec: libc::suseconds_t::from(value.timestamp_subsec_micros()),
        }
    }
}

impl DefaultZeroed for timeval {}

impl timeval {
    pub fn now() -> Self {
        (&Utc::now()).into()
    }
}
