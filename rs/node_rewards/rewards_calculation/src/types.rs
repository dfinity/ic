use chrono::{DateTime, NaiveDateTime, ParseError, Utc};
use ic_base_types::NodeId;
use ic_protobuf::registry::node::v1::NodeRewardType;
use serde::{Deserialize, Serialize};
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

impl DayUtc {
    pub fn from_nanos(value: UnixTsNanos) -> Self {
        let day_end = ((value / NANOS_PER_DAY) + 1) * NANOS_PER_DAY - 1;
        Self { value: day_end }
    }

    pub fn from_secs(value: u64) -> Self {
        let nanos = value * 1_000_000_000;
        Self::from_nanos(nanos)
    }
}

impl Display for DayUtc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dd_mm_yyyy =
            DateTime::from_timestamp_nanos(self.unix_ts_at_day_end_nanoseconds() as i64)
                .naive_utc()
                .format("%d-%m-%Y")
                .to_string();
        write!(f, "{}", dd_mm_yyyy)
    }
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

impl DayUtc {
    pub fn unix_ts_at_day_end_nanoseconds(&self) -> UnixTsNanos {
        self.value
    }

    pub fn get(&self) -> UnixTsNanos {
        self.value
    }

    pub fn unix_ts_at_day_start_nanoseconds(&self) -> UnixTsNanos {
        (self.value / NANOS_PER_DAY) * NANOS_PER_DAY
    }

    pub fn unix_ts_at_day_end_seconds(&self) -> u64 {
        self.unix_ts_at_day_end_nanoseconds() / 1_000_000_000
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
        let from_day: DayUtc = ymdh_to_ts(2020, 1, 12, 0).into();
        let to_day = (ymdh_to_ts(2020, 1, 16, 0) - 1).into();
        let days = from_day.days_until(&to_day).unwrap().len();

        assert_eq!(days, 4);

        let to_day = ymdh_to_ts(2020, 1, 12, 13).into();
        let days = from_day.days_until(&to_day).unwrap().len();

        assert_eq!(days, 1);
    }
}
