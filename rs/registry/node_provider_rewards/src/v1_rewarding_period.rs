use crate::v1_types::TimestampNanos;
use ic_types::Time;
use std::error::Error;
use std::fmt;

const HR_NANOS: u64 = 60 * 60 * 1_000_000_000;
const DAY_IN_NANOS: u64 = HR_NANOS * 24;

#[cfg(target_arch = "wasm32")]
fn current_time() -> Time {
    let current_time = ic_cdk::api::time();
    Time::from_nanos_since_unix_epoch(current_time)
}

#[cfg(not(any(target_arch = "wasm32")))]
fn current_time() -> Time {
    ic_types::time::current_time()
}

#[derive(Debug, PartialEq)]
pub enum RewardingPeriodError {
    FromTimestampAfterToTimestamp,
    ToTimestampNotInPast,
}

impl fmt::Display for RewardingPeriodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RewardingPeriodError::FromTimestampAfterToTimestamp => {
                write!(f, "from_ts must be earlier than to_ts.")
            }
            RewardingPeriodError::ToTimestampNotInPast => {
                write!(
                    f,
                    "from_ts must be earlier than today.\
                Management canister metrics are collected at midnight UTC."
                )
            }
        }
    }
}

impl Error for RewardingPeriodError {}

#[derive(Clone, Debug)]
pub struct RewardingPeriod {
    from_ts: TimestampNanos,
    to_ts: TimestampNanos,
}

impl RewardingPeriod {
    pub fn new(
        from_ts: TimestampNanos,
        to_ts: TimestampNanos,
    ) -> Result<Self, RewardingPeriodError> {
        let now = current_time().as_nanos_since_unix_epoch() as TimestampNanos;
        let beginning_today = now / DAY_IN_NANOS * DAY_IN_NANOS;

        if to_ts >= beginning_today {
            return Err(RewardingPeriodError::ToTimestampNotInPast);
        }
        if from_ts >= to_ts {
            return Err(RewardingPeriodError::FromTimestampAfterToTimestamp);
        }

        Ok(Self {
            from_ts: from_ts / DAY_IN_NANOS * DAY_IN_NANOS,
            to_ts: to_ts / DAY_IN_NANOS * DAY_IN_NANOS + DAY_IN_NANOS,
        })
    }
    pub fn days_between(&self) -> u64 {
        (self.to_ts - self.from_ts) / DAY_IN_NANOS
    }

    pub fn start_metrics_ts(&self) -> TimestampNanos {
        self.from_ts + HR_NANOS
    }

    pub fn end_metrics_ts(&self) -> TimestampNanos {
        self.to_ts + HR_NANOS
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
        let from_ts = ymdh_to_ts(2020, 1, 12, 12);
        let to_ts = ymdh_to_ts(2020, 1, 15, 15);
        let rp = RewardingPeriod::new(from_ts, to_ts).unwrap();

        let expected_from_ts = ymdh_to_ts(2020, 1, 12, 1);
        let expected_to_ts = ymdh_to_ts(2020, 1, 16, 1);

        assert_eq!(rp.start_metrics_ts(), expected_from_ts);
        assert_eq!(rp.end_metrics_ts(), expected_to_ts);
        assert_eq!(rp.days_between(), 4);

        let to_ts = ymdh_to_ts(2020, 1, 12, 13);
        let rp = RewardingPeriod::new(from_ts, to_ts).unwrap();
        assert_eq!(rp.days_between(), 1);
    }

    #[test]
    fn test_error_to_ts_not_in_past() {
        let to_ts = current_time().as_nanos_since_unix_epoch() as TimestampNanos;
        let from_ts = 0;

        let rp = RewardingPeriod::new(from_ts, to_ts);
        assert_eq!(rp.unwrap_err(), RewardingPeriodError::ToTimestampNotInPast);
    }

    #[test]
    fn test_error_to_ts_grater_from_ts() {
        let to_ts = 0;
        let from_ts = 1;

        let rp = RewardingPeriod::new(from_ts, to_ts);
        assert_eq!(
            rp.unwrap_err(),
            RewardingPeriodError::FromTimestampAfterToTimestamp
        );
    }
}
