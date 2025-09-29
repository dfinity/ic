pub mod monthly_rewards;
pub mod provider_rewards_calculation;
pub mod providers_rewards;

use rewards_calculation::types as native_types;

// These are API-facing types with all fields wrapped in `Option`
// to ensure deserialization always works
// in the future without breaking clients that consume the API.
#[derive(
    PartialOrd, Ord, Eq, candid::CandidType, candid::Deserialize, Clone, Copy, PartialEq, Debug,
)]
pub struct DayUtc {
    last_ts_nanoseconds: Option<u64>,
}

impl DayUtc {
    pub fn from_nanos(nanos_since_unix_epoch: u64) -> Self {
        Self::from(native_types::DayUtc::from_nanos(nanos_since_unix_epoch))
    }

    pub fn from_secs(secs_since_unix_epoch: u64) -> Self {
        Self::from(native_types::DayUtc::from_secs(secs_since_unix_epoch))
    }
}

impl From<native_types::DayUtc> for DayUtc {
    fn from(day_utc: native_types::DayUtc) -> Self {
        Self {
            last_ts_nanoseconds: Some(day_utc.unix_timestamp_at_day_end_nanoseconds()),
        }
    }
}

impl From<DayUtc> for native_types::DayUtc {
    fn from(day_utc: DayUtc) -> Self {
        native_types::DayUtc::from_nanos(
            day_utc
                .last_ts_nanoseconds
                .expect("last_ts_nanoseconds is None"),
        )
    }
}
