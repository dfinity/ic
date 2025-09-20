use candid::CandidType;
use ic_stable_structures::{Storable, storable::Bound};
use minicbor::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::convert::TryInto;
use std::ops::{Add, Sub};
use std::time::{Duration, SystemTime};

#[cfg(test)]
mod tests;

#[derive(
    Copy,
    Clone,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Debug,
    CandidType,
    Deserialize,
    Serialize,
    Encode,
    Decode,
)]
pub struct TimeStamp {
    #[n(0)]
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
        Self {
            timestamp_nanos: self
                .timestamp_nanos
                .saturating_add(d.as_nanos().try_into().unwrap()),
        }
    }
}

impl Sub<Duration> for TimeStamp {
    type Output = Self;

    fn sub(self, d: Duration) -> Self {
        Self {
            timestamp_nanos: self
                .timestamp_nanos
                .saturating_sub(d.as_nanos().try_into().unwrap()),
        }
    }
}

impl Storable for TimeStamp {
    fn to_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Owned(self.as_nanos_since_unix_epoch().to_le_bytes().to_vec())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Self::from_nanos_since_unix_epoch(u64::from_le_bytes(
            bytes.into_owned().as_slice().try_into().unwrap(),
        ))
    }

    const BOUND: Bound = Bound::Bounded {
        max_size: 8,
        is_fixed_size: true,
    };
}
