use candid::CandidType;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::ops::{Add, Sub};
use std::time::{Duration, SystemTime};

#[derive(
    Debug, Clone, Copy, CandidType, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
pub struct TimeStamp {
    timestamp_nanos: u64,
}

impl TimeStamp {
    pub fn new(secs: u64, nanos: u32) -> Self {
        assert!(nanos < 1_000_000_000);
        Self {
            timestamp_nanos: secs * 1_000_000_000 + nanos as u64,
        }
    }

    pub fn from_nanos_since_unix_epoch(nanos: u64) -> Self {
        Self {
            timestamp_nanos: nanos,
        }
    }

    pub fn as_nanos_since_unix_epoch(&self) -> u64 {
        self.timestamp_nanos
    }
}

impl From<SystemTime> for TimeStamp {
    fn from(t: SystemTime) -> Self {
        let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        Self::from_nanos_since_unix_epoch(d.as_nanos().try_into().unwrap())
    }
}

impl From<TimeStamp> for SystemTime {
    fn from(t: TimeStamp) -> Self {
        SystemTime::UNIX_EPOCH + Duration::from_nanos(t.timestamp_nanos)
    }
}

impl Add<Duration> for TimeStamp {
    type Output = Self;

    fn add(self, d: Duration) -> Self {
        (SystemTime::from(self) + d).into()
    }
}

impl Sub<Duration> for TimeStamp {
    type Output = Self;

    fn sub(self, d: Duration) -> Self {
        (SystemTime::from(self) - d).into()
    }
}
