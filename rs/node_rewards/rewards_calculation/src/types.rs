use crate::rewards_calculator_results::DayUTC;
use ic_base_types::{NodeId, PrincipalId, SubnetId};
use ic_types::Time;
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fmt::Display;

pub type UnixTsNanos = u64;
pub const NANOS_PER_DAY: UnixTsNanos = 24 * 60 * 60 * 1_000_000_000;

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
    pub from: DayUTC,
    pub to: DayUTC,
}

impl RewardPeriod {
    pub fn days(&self) -> Vec<DayUTC> {
        self.from.days_until(&self.to).expect("Always valid days")
    }
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
    /// Creates a new `RewardPeriod` from two unaligned timestamps.
    ///
    /// # Arguments
    /// * `unaligned_start_ts` - A generic timestamp (in nanoseconds) in the first (UTC) day.
    /// * `unaligned_end_ts` - A generic timestamp (in nanoseconds) in the last (UTC) day.
    pub fn new(
        unaligned_start_ts: UnixTsNanos,
        unaligned_end_ts: UnixTsNanos,
    ) -> Result<Self, RewardPeriodError> {
        if unaligned_start_ts > unaligned_end_ts {
            return Err(RewardPeriodError::StartTimestampAfterEndTimestamp);
        }
        let start_day: DayUTC = unaligned_start_ts.into();
        let end_day: DayUTC = unaligned_end_ts.into();

        // Metrics are collected at the end of the day, so we need to ensure that
        // the end timestamp is not later than the first ts of today.
        let today: DayUTC = current_time().as_nanos_since_unix_epoch().into();

        if end_day >= today {
            return Err(RewardPeriodError::EndTimestampLaterThanToday);
        }

        Ok(Self {
            from: start_day,
            to: end_day,
        })
    }

    pub fn contains(&self, day: DayUTC) -> bool {
        day >= self.from && day <= self.to
    }
}

#[derive(Debug, PartialEq)]
pub enum RewardPeriodError {
    StartTimestampAfterEndTimestamp,
    EndTimestampLaterThanToday,
}

impl fmt::Display for RewardPeriodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RewardPeriodError::StartTimestampAfterEndTimestamp => {
                write!(
                    f,
                    "unaligned_start_ts must be earlier than unaligned_end_ts."
                )
            }
            RewardPeriodError::EndTimestampLaterThanToday => {
                write!(f, "unaligned_end_ts must be earlier than today")
            }
        }
    }
}

impl Error for RewardPeriodError {}

#[derive(Eq, Hash, PartialEq, Clone, Ord, PartialOrd, Debug, Default)]
pub struct Region(pub String);
#[derive(Eq, Hash, PartialEq, Clone, Ord, PartialOrd, Debug, Default)]
pub struct NodeType(pub String);

#[derive(Default)]
pub struct ProviderRewardableNodes {
    pub provider_id: PrincipalId,
    pub rewardable_nodes_count: HashMap<(Region, NodeType), u32>,
    pub rewardable_nodes: Vec<RewardableNode>,
}
#[derive(Eq, Hash, PartialEq, Clone, Ord, PartialOrd, Debug)]
pub struct RewardableNode {
    pub node_id: NodeId,
    pub rewardable_days: Vec<DayUTC>,
    pub region: Region,
    // TODO: remove this when rewards_calculation is performed with NodeRewardType
    pub node_type: NodeType,
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
    pub day: DayUTC,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewards_calculator_results::days_between;
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
        let unaligned_start_ts = ymdh_to_ts(2020, 1, 12, 12);
        let unaligned_end_ts = ymdh_to_ts(2020, 1, 15, 15);

        let rp = RewardPeriod::new(unaligned_start_ts, unaligned_end_ts).unwrap();
        let expected_start_ts = ymdh_to_ts(2020, 1, 12, 0);
        let expected_end_ts = ymdh_to_ts(2020, 1, 16, 0) - 1;
        let days = days_between(rp.from, rp.to);

        assert_eq!(rp.from.unix_ts_at_day_start(), expected_start_ts);
        assert_eq!(rp.to.unix_ts_at_day_end(), expected_end_ts);
        assert_eq!(days, 4);

        let unaligned_end_ts = ymdh_to_ts(2020, 1, 12, 13);

        let rp = RewardPeriod::new(unaligned_start_ts, unaligned_end_ts).unwrap();
        let days = days_between(rp.from, rp.to);

        assert_eq!(days, 1);
    }

    #[test]
    fn test_error_too_recent_end_ts() {
        let to_ts = current_time().as_nanos_since_unix_epoch();
        let from_ts = 0;

        let rp = RewardPeriod::new(from_ts, to_ts);
        assert_eq!(
            rp.unwrap_err(),
            RewardPeriodError::EndTimestampLaterThanToday
        );
    }

    #[test]
    fn test_error_unaligned_start_ts_greater_unaligned_end_ts() {
        let to_ts = 0;
        let from_ts = 1;

        let rp = RewardPeriod::new(from_ts, to_ts);

        assert_eq!(
            rp.unwrap_err(),
            RewardPeriodError::StartTimestampAfterEndTimestamp
        );
    }
}
