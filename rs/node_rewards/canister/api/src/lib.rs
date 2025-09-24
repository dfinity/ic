pub mod monthly_rewards;
pub mod provider_rewards_calculation;
pub mod providers_rewards;

// These are API-facing types with all fields wrapped in `Option`
// to ensure forward compatibility. This way, new fields can be added
// in the future without breaking clients that consume the API.
#[derive(
    PartialOrd, Ord, Eq, candid::CandidType, candid::Deserialize, Clone, Copy, PartialEq, Debug,
)]
pub struct DayUtc {
    last_ts_nanoseconds: Option<u64>,
}

impl DayUtc {
    pub fn from_nanos(nanos_since_unix_epoch: u64) -> Self {
        Self::from(rewards_calculation::types::DayUtc::from_nanos(
            nanos_since_unix_epoch,
        ))
    }

    pub fn from_secs(secs_since_unix_epoch: u64) -> Self {
        Self::from(rewards_calculation::types::DayUtc::from_secs(
            secs_since_unix_epoch,
        ))
    }
}

impl From<rewards_calculation::types::DayUtc> for DayUtc {
    fn from(day_utc: rewards_calculation::types::DayUtc) -> Self {
        Self {
            last_ts_nanoseconds: Some(day_utc.last_ts_nanos()),
        }
    }
}

impl From<DayUtc> for rewards_calculation::types::DayUtc {
    fn from(day_utc: DayUtc) -> Self {
        rewards_calculation::types::DayUtc::from_nanos(
            day_utc
                .last_ts_nanoseconds
                .expect("last_ts_nanoseconds is None"),
        )
    }
}
