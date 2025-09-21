use rewards_calculation::types;
use rewards_calculation::types::UnixTsNanos;

pub mod monthly_rewards;
pub mod provider_rewards_calculation;
pub mod providers_rewards;
const NANOS_PER_DAY: UnixTsNanos = 24 * 60 * 60 * 1_000_000_000;

#[derive(
    PartialOrd, Ord, Eq, candid::CandidType, candid::Deserialize, Clone, Copy, PartialEq, Debug,
)]
pub struct DayUtc {
    last_ts_nanoseconds: Option<u64>,
}

impl DayUtc {
    pub fn from_nanos(value: u64) -> Self {
        let last_ts_nanoseconds = ((value / NANOS_PER_DAY) + 1) * NANOS_PER_DAY - 1;
        Self {
            last_ts_nanoseconds: Some(last_ts_nanoseconds),
        }
    }

    pub fn from_secs(value: u64) -> Self {
        let nanos = value * 1_000_000_000;
        Self::from_nanos(nanos)
    }
}

// DayUtc conversions
impl From<types::DayUtc> for DayUtc {
    fn from(day_utc: types::DayUtc) -> Self {
        Self {
            last_ts_nanoseconds: Some(day_utc.last_ts_nanos()),
        }
    }
}

impl From<DayUtc> for types::DayUtc {
    fn from(day_utc: DayUtc) -> Self {
        types::DayUtc::from_nanos(
            day_utc
                .last_ts_nanoseconds
                .expect("last_ts_nanoseconds is None"),
        )
    }
}
