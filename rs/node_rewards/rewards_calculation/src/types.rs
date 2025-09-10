use chrono::{DateTime, NaiveDateTime, ParseError, Utc};
use ic_base_types::{NodeId, SubnetId};
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_types::Time;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;
use std::fmt::Display;

pub type UnixTsNanos = u64;
pub type NodesCount = u64;

pub type Region = String;

const NANOS_PER_DAY: UnixTsNanos = 24 * 60 * 60 * 1_000_000_000;

#[derive(Clone, Debug, PartialEq, Hash, PartialOrd, Ord, Eq, Copy, Deserialize, Serialize)]
pub struct DayUtc {
    value: UnixTsNanos,
}

impl From<UnixTsNanos> for DayUtc {
    fn from(value: UnixTsNanos) -> Self {
        let day_end = ((value / NANOS_PER_DAY) + 1) * NANOS_PER_DAY - 1;
        Self { value: day_end }
    }
}

impl TryFrom<&str> for DayUtc {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let dt = format!("{} 00:00:00", value);
        let naive = NaiveDateTime::parse_from_str(&dt, "%Y-%m-%d %H:%M:%S")?;
        let datetime: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive, Utc);
        let ts = datetime.timestamp_nanos_opt().unwrap() as u64;

        Ok(DayUtc::from(ts))
    }
}

impl Default for DayUtc {
    fn default() -> Self {
        DayUtc::from(0)
    }
}

impl Display for DayUtc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dd_mm_yyyy = DateTime::from_timestamp_nanos(self.unix_ts_at_day_end() as i64)
            .naive_utc()
            .format("%d-%m-%Y")
            .to_string();

        write!(f, "{}", dd_mm_yyyy)
    }
}

impl DayUtc {
    pub fn unix_ts_at_day_end(&self) -> UnixTsNanos {
        self.value
    }

    pub fn get(&self) -> UnixTsNanos {
        self.value
    }

    pub fn unix_ts_at_day_start(&self) -> UnixTsNanos {
        (self.value / NANOS_PER_DAY) * NANOS_PER_DAY
    }

    pub fn next_day(&self) -> DayUtc {
        DayUtc {
            value: self.value + NANOS_PER_DAY,
        }
    }

    pub fn previous_day(&self) -> DayUtc {
        let ts_previous_day = self.value.checked_sub(NANOS_PER_DAY).unwrap_or_default();
        DayUtc {
            value: ts_previous_day,
        }
    }

    pub fn days_until(&self, other: &DayUtc) -> Result<Vec<DayUtc>, String> {
        if self > other {
            return Err(format!(
                "Cannot compute days_until: {} > {}",
                self.value, other.value
            ));
        }

        let num_days = (other.value - self.value) / NANOS_PER_DAY;
        let days_until = (0..=num_days)
            .map(|i| DayUtc {
                value: self.value + i * NANOS_PER_DAY,
            })
            .collect();

        Ok(days_until)
    }
}

#[cfg(target_arch = "wasm32")]
fn current_time() -> Time {
    let current_time = ic_cdk::api::time();
    Time::from_nanos_since_unix_epoch(current_time)
}

#[cfg(not(any(target_arch = "wasm32")))]
fn current_time() -> Time {
    ic_types::time::current_time()
}

/// Reward period in which we want to reward the node providers
///
/// This period ensures that all `BlockmakerMetrics` collected during the reward period are included consistently
/// with the invariant defined in [`ic_replicated_state::metadata_state::BlockmakerMetricsTimeSeries`].
#[derive(Debug, Clone, PartialEq)]
pub struct RewardPeriod {
    pub from: DayUtc,
    pub to: DayUtc,
}

impl Display for RewardPeriod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RewardPeriod: {} - {}",
            self.from.unix_ts_at_day_start(),
            self.to.unix_ts_at_day_end()
        )
    }
}

impl RewardPeriod {
    pub fn new(from: DayUtc, to: DayUtc) -> Result<Self, RewardPeriodError> {
        if from > to {
            return Err(RewardPeriodError::FromDayUtcLaterThanToDayUtc);
        }

        // Metrics are collected at the end of the day, so we need to ensure that
        // the end timestamp is not later than the first ts of today.
        let today: DayUtc = current_time().as_nanos_since_unix_epoch().into();

        if to >= today {
            return Err(RewardPeriodError::ToDayUtcLaterThanToday);
        }

        Ok(Self { from, to })
    }

    pub fn contains(&self, day: DayUtc) -> bool {
        day >= self.from && day <= self.to
    }
}

#[derive(Debug, PartialEq)]
pub enum RewardPeriodError {
    FromDayUtcLaterThanToDayUtc,
    ToDayUtcLaterThanToday,
}

impl fmt::Display for RewardPeriodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RewardPeriodError::FromDayUtcLaterThanToDayUtc => {
                write!(f, "FromDayUtc must be earlier or equal ToDayUtc.")
            }
            RewardPeriodError::ToDayUtcLaterThanToday => {
                write!(f, "ToDayUtc must be earlier than today")
            }
        }
    }
}

impl Error for RewardPeriodError {}

#[derive(Eq, Hash, PartialEq, Clone, Ord, PartialOrd, Debug)]
pub struct RewardableNode {
    pub node_id: NodeId,
    pub rewardable_days: Vec<DayUtc>,
    pub region: Region,
    pub node_reward_type: NodeRewardType,
    pub dc_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeMetricsDailyRaw {
    pub node_id: NodeId,
    pub num_blocks_proposed: u64,
    pub num_blocks_failed: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct SubnetMetricsDailyKey {
    pub subnet_id: SubnetId,
    pub day: DayUtc,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::UnixTsNanos;
    use chrono::{TimeZone, Utc};

    fn ymdh_to_ts(year: i32, month: u32, day: u32, hour: u32) -> UnixTsNanos {
        Utc.with_ymd_and_hms(year, month, day, hour, 0, 0)
            .unwrap()
            .timestamp_nanos_opt()
            .unwrap() as UnixTsNanos
    }

    #[test]
    fn test_valid_rewarding_period() {
        let from_ts = ymdh_to_ts(2020, 1, 12, 12);
        let end_ts = ymdh_to_ts(2020, 1, 15, 15);

        let rp = RewardPeriod::new(DayUtc::from(from_ts), DayUtc::from(end_ts)).unwrap();
        let expected_start_ts = ymdh_to_ts(2020, 1, 12, 0);
        let expected_end_ts = ymdh_to_ts(2020, 1, 16, 0) - 1;
        let days = rp.from.days_until(&rp.to).unwrap().len();

        assert_eq!(rp.from.unix_ts_at_day_start(), expected_start_ts);
        assert_eq!(rp.to.unix_ts_at_day_end(), expected_end_ts);
        assert_eq!(days, 4);

        let end_ts = ymdh_to_ts(2020, 1, 12, 13);

        let rp = RewardPeriod::new(DayUtc::from(from_ts), DayUtc::from(end_ts)).unwrap();
        let days = rp.from.days_until(&rp.to).unwrap().len();

        assert_eq!(days, 1);
    }

    #[test]
    fn test_error_too_recent_end_ts() {
        let to_ts = current_time().as_nanos_since_unix_epoch();
        let from_ts = 0;

        let rp = RewardPeriod::new(DayUtc::from(from_ts), DayUtc::from(to_ts));
        assert_eq!(rp.unwrap_err(), RewardPeriodError::ToDayUtcLaterThanToday);
    }

    #[test]
    fn test_error_unaligned_start_ts_greater_unaligned_end_ts() {
        let to_ts = 0;
        let from_ts = 86499999999999;

        let rp = RewardPeriod::new(DayUtc::from(from_ts), DayUtc::from(to_ts));

        assert_eq!(
            rp.unwrap_err(),
            RewardPeriodError::FromDayUtcLaterThanToDayUtc
        );
    }
}
