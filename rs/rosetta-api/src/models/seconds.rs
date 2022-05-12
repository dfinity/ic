use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
/// A number of seconds since Unix epoch.
pub struct Seconds(pub u64);

impl From<Seconds> for Duration {
    fn from(s: Seconds) -> Self {
        Duration::from_secs(s.0)
    }
}

impl From<Duration> for Seconds {
    fn from(d: Duration) -> Self {
        Seconds(d.as_secs())
    }
}

impl From<SystemTime> for Seconds {
    fn from(t: SystemTime) -> Self {
        Seconds::from(t.duration_since(SystemTime::UNIX_EPOCH).unwrap())
    }
}
