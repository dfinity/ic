use crate::v1_types::TimestampNanos;
use ic_types::Time;
use std::error::Error;
use std::fmt;
use std::fmt::Display;

pub const NANOS_PER_DAY: TimestampNanos = 24 * 60 * 60 * 1_000_000_000;

#[cfg(target_arch = "wasm32")]
fn current_time() -> Time {
    let current_time = ic_cdk::api::time();
    Time::from_nanos_since_unix_epoch(current_time)
}

#[cfg(not(any(target_arch = "wasm32")))]
fn current_time() -> Time {
    ic_types::time::current_time()
}

/// Represents an arbitrary timestamp that has not been aligned to start/end of the day.
/// This is useful for constructing a RewardPeriods from arbitrary timestamps.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UnalignedTimestamp(TimestampNanos);

impl From<TimestampNanos> for UnalignedTimestamp {
    fn from(ts: TimestampNanos) -> Self {
        Self(ts)
    }
}

impl UnalignedTimestamp {
    pub fn new(timestamp: TimestampNanos) -> Self {
        Self(timestamp)
    }

    pub fn align_to_day_start(self) -> TimestampNanos {
        (self.0 / NANOS_PER_DAY) * NANOS_PER_DAY
    }

    pub fn align_to_day_end(self) -> TimestampNanos {
        ((self.0 / NANOS_PER_DAY) + 1) * NANOS_PER_DAY - 1
    }
}

#[derive(Debug, PartialEq)]
pub enum RewardPeriodError {
    FromTimestampAfterToTimestamp,
    TooRecentEndTimestamp,
}

impl fmt::Display for RewardPeriodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RewardPeriodError::FromTimestampAfterToTimestamp => {
                write!(
                    f,
                    "unaligned_start_ts must be earlier than unaligned_end_ts."
                )
            }
            RewardPeriodError::TooRecentEndTimestamp => {
                write!(f, "unaligned_end_ts must be earlier than today")
            }
        }
    }
}

impl Error for RewardPeriodError {}

// Reward period spanning over two timestamp boundaries:
//  - `start_ts`: The first timestamp (in nanoseconds) of the day.
//  - `end_ts`: The last timestamp (in nanoseconds) of the day.
//
// This period is derived from two unaligned timestamps, which are then adjusted to align with
// the start and end of their respective days.
// This ensures that all `BlockmakerMetrics` collected during the reward period are included consistently
// with the invariant defined in [`ic_replicated_state::metadata_state::BlockmakerMetricsTimeSeries`].
#[derive(Debug, Clone, PartialEq)]
pub struct RewardPeriod {
    start_ts: TimestampNanos,
    end_ts: TimestampNanos,
}

impl Display for RewardPeriod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RewardPeriod: {} - {}", self.start_ts, self.end_ts)
    }
}

impl RewardPeriod {
    pub fn new(
        unaligned_start_ts: UnalignedTimestamp,
        unaligned_end_ts: UnalignedTimestamp,
    ) -> Result<Self, RewardPeriodError> {
        if unaligned_start_ts.0 >= unaligned_end_ts.0 {
            return Err(RewardPeriodError::FromTimestampAfterToTimestamp);
        }

        let current_ts = UnalignedTimestamp(current_time().as_nanos_since_unix_epoch());
        let today_start_ts = current_ts.align_to_day_start();
        if unaligned_end_ts.0 >= today_start_ts {
            return Err(RewardPeriodError::TooRecentEndTimestamp);
        }

        Ok(Self {
            start_ts: unaligned_start_ts.align_to_day_start(),
            end_ts: unaligned_end_ts.align_to_day_end(),
        })
    }

    pub fn contains(&self, ts: TimestampNanos) -> bool {
        ts >= self.start_ts && ts <= self.end_ts
    }

    pub fn days_between(&self) -> u64 {
        ((self.end_ts - self.start_ts) / NANOS_PER_DAY) + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};

    fn ymdh_to_ts(year: i32, month: u32, day: u32, hour: u32) -> TimestampNanos {
        Utc.with_ymd_and_hms(year, month, day, hour, 0, 0)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap() as TimestampNanos
    }

    #[test]
    fn test_valid_rewarding_period() {
        let unaligned_start_ts = ymdh_to_ts(2020, 1, 12, 12);
        let unaligned_end_ts = ymdh_to_ts(2020, 1, 15, 15);

        let rp = RewardPeriod::new(unaligned_start_ts.into(), unaligned_end_ts.into()).unwrap();
        let expected_start_ts = ymdh_to_ts(2020, 1, 12, 0);
        let expected_end_ts = ymdh_to_ts(2020, 1, 16, 0) - 1;

        assert_eq!(rp.start_ts, expected_start_ts);
        assert_eq!(rp.end_ts, expected_end_ts);
        assert_eq!(rp.days_between(), 4);

        let unaligned_end_ts = ymdh_to_ts(2020, 1, 12, 13);

        let rp = RewardPeriod::new(unaligned_start_ts.into(), unaligned_end_ts.into()).unwrap();

        assert_eq!(rp.days_between(), 1);
    }

    #[test]
    fn test_error_too_recent_end_ts() {
        let to_ts = current_time().as_nanos_since_unix_epoch() as TimestampNanos;
        let from_ts = 0;

        let rp = RewardPeriod::new(from_ts.into(), to_ts.into());
        assert_eq!(rp.unwrap_err(), RewardPeriodError::TooRecentEndTimestamp);
    }

    #[test]
    fn test_error_unaligned_start_ts_greater_unaligned_end_ts() {
        let to_ts = 0;
        let from_ts = 1;

        let rp = RewardPeriod::new(from_ts.into(), to_ts.into());

        assert_eq!(
            rp.unwrap_err(),
            RewardPeriodError::FromTimestampAfterToTimestamp
        );
    }
}
