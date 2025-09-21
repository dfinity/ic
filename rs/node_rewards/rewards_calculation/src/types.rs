use chrono::{DateTime, NaiveDateTime, ParseError, Utc};
use ic_base_types::NodeId;
use ic_protobuf::registry::node::v1::NodeRewardType;
use ic_types::Time;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fmt::Display;

pub type UnixTsNanos = u64;
pub type NodesCount = u64;
pub type Region = String;

const NANOS_PER_DAY: UnixTsNanos = 24 * 60 * 60 * 1_000_000_000;

#[derive(Clone, Debug, PartialEq, Hash, PartialOrd, Ord, Eq, Copy, Deserialize, Serialize)]
pub struct DayUtc {
    last_ts_nanoseconds: u64,
}

impl DayUtc {
    pub fn from_nanos(value: u64) -> Self {
        Self {
            last_ts_nanoseconds: ((value / NANOS_PER_DAY) + 1) * NANOS_PER_DAY - 1,
        }
    }

    pub fn from_secs(value: u64) -> Self {
        let nanos = value * 1_000_000_000;
        Self::from_nanos(nanos)
    }
}

impl From<Time> for DayUtc {
    fn from(value: Time) -> Self {
        Self::from_nanos(value.as_nanos_since_unix_epoch())
    }
}

impl Display for DayUtc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dd_mm_yyyy = DateTime::from_timestamp_nanos(self.last_ts_nanos() as i64)
            .naive_utc()
            .format("%d-%m-%Y")
            .to_string();
        write!(f, "{}", dd_mm_yyyy)
    }
}

impl TryFrom<&str> for DayUtc {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let dt = format!("{} 00:00:00", value);
        let naive = NaiveDateTime::parse_from_str(&dt, "%Y-%m-%d %H:%M:%S")?;
        let datetime: DateTime<Utc> = DateTime::from_naive_utc_and_offset(naive, Utc);
        let ts = datetime.timestamp_nanos_opt().unwrap() as u64;

        Ok(DayUtc::from_nanos(ts))
    }
}

impl Default for DayUtc {
    fn default() -> Self {
        DayUtc::from_nanos(0)
    }
}

impl DayUtc {
    pub fn last_ts_nanos(&self) -> u64 {
        self.last_ts_nanoseconds
    }

    pub fn first_ts_nanos(&self) -> u64 {
        (self.last_ts_nanoseconds / NANOS_PER_DAY) * NANOS_PER_DAY
    }

    pub fn last_ts_secs(&self) -> u64 {
        self.last_ts_nanos() / 1_000_000_000
    }

    pub fn first_ts_secs(&self) -> u64 {
        self.first_ts_nanos() / 1_000_000_000
    }

    pub fn next_day(&self) -> DayUtc {
        DayUtc {
            last_ts_nanoseconds: self.last_ts_nanoseconds + NANOS_PER_DAY,
        }
    }

    pub fn previous_day(&self) -> DayUtc {
        let ts_previous_day = self
            .last_ts_nanoseconds
            .checked_sub(NANOS_PER_DAY)
            .unwrap_or_default();
        DayUtc {
            last_ts_nanoseconds: ts_previous_day,
        }
    }

    pub fn days_until(&self, other: &DayUtc) -> Result<Vec<DayUtc>, String> {
        if self > other {
            return Err(format!(
                "Cannot compute days_until: {} > {}",
                self.last_ts_nanoseconds, other.last_ts_nanoseconds
            ));
        }

        let num_days = (other.last_ts_nanoseconds - self.last_ts_nanoseconds) / NANOS_PER_DAY;
        let days_until = (0..=num_days)
            .map(|i| DayUtc {
                last_ts_nanoseconds: self.last_ts_nanoseconds + i * NANOS_PER_DAY,
            })
            .collect();

        Ok(days_until)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct NodeMetricsDailyRaw {
    pub node_id: NodeId,
    pub num_blocks_proposed: u64,
    pub num_blocks_failed: u64,
}

#[derive(Eq, Hash, PartialEq, Clone, Ord, PartialOrd, Debug)]
pub struct RewardableNode {
    pub node_id: NodeId,
    pub region: Region,
    pub node_reward_type: NodeRewardType,
    pub dc_id: String,
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
        let from_day: DayUtc = DayUtc::from_nanos(ymdh_to_ts(2020, 1, 12, 0));
        let to_day: DayUtc = DayUtc::from_nanos(ymdh_to_ts(2020, 1, 15, 0));

        let days = from_day.days_until(&to_day).unwrap().len();

        assert_eq!(days, 4);

        let to_day = DayUtc::from_nanos(ymdh_to_ts(2020, 1, 12, 13));
        let days = from_day.days_until(&to_day).unwrap().len();

        assert_eq!(days, 1);
    }
}
