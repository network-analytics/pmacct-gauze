use crate::timeval;
use chrono::{DateTime, TimeZone, Utc};

impl<T: TimeZone> From<&DateTime<T>> for timeval {
    fn from(value: &DateTime<T>) -> Self {
        Self {
            tv_sec: value.timestamp(),
            tv_usec: libc::suseconds_t::from(value.timestamp_subsec_micros()),
        }
    }
}

#[allow(clippy::derivable_impls)]
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
