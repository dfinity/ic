use candid::{CandidType, Deserialize};
use serde::Serialize;
use std::fmt::Display;

pub mod monthly_rewards;
pub mod provider_rewards_calculation;
pub mod providers_rewards;

type UnixTsNanos = u64;

#[derive(CandidType, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DayUtc {
    pub value: UnixTsNanos,
}

impl From<UnixTsNanos> for DayUtc {
    fn from(value: UnixTsNanos) -> Self {
        Self {
            value: rewards_calculation::types::DayUtc::from(value).unix_ts_at_day_end(),
        }
    }
}

impl From<DayUtc> for rewards_calculation::types::DayUtc {
    fn from(value: DayUtc) -> Self {
        Self::from(value.value)
    }
}

impl From<rewards_calculation::types::DayUtc> for DayUtc {
    fn from(value: rewards_calculation::types::DayUtc) -> Self {
        Self::from(value.value)
    }
}
