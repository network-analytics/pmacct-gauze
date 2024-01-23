use chrono::{DateTime, TimeZone, Utc};
use crate::{__suseconds_t, timeval};

impl<T: TimeZone> From<&DateTime<T>> for timeval {
    fn from(value: &DateTime<T>) -> Self {
        Self {
            tv_sec: value.timestamp(),
            tv_usec: __suseconds_t::from(value.timestamp_subsec_micros()),
        }
    }
}

impl Default for timeval {
    fn default() -> Self {
        Self {
            tv_sec: 0,
            tv_usec: 0,
        }
    }
}

impl timeval {
    pub fn now() -> Self {
        (&Utc::now()).into()
    }
}