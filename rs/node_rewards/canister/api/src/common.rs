use chrono::{DateTime, Utc};
use rewards_calculation::rewards_calculator_results;
use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;

#[derive(candid::CandidType, candid::Deserialize, Clone)]
pub struct RewardPeriodArgs {
    /// Start of the reward distribution period, as a Unix timestamp in nanoseconds.
    /// This timestamp covers the entire correspondent UTC day and is inclusive.
    pub start_ts: u64,

    /// End of the reward distribution period, as a Unix timestamp in nanoseconds.
    /// This timestamp covers the entire correspondent UTC day and is inclusive.
    pub end_ts: u64,
}

fn decimal_to_f64(value: Decimal) -> Result<f64, String> {
    value
        .round_dp(4)
        .to_f64()
        .ok_or_else(|| "Failed to convert Decimal to f64".to_string())
}

#[derive(candid::CandidType, candid::Deserialize)]
pub struct XDRPermyriad(f64);
impl TryFrom<rewards_calculator_results::XDRPermyriad> for XDRPermyriad {
    type Error = String;

    fn try_from(value: rewards_calculator_results::XDRPermyriad) -> Result<Self, Self::Error> {
        Ok(Self(decimal_to_f64(value.get())?))
    }
}

#[derive(candid::CandidType, candid::Deserialize)]
pub struct Percent(f64);
impl TryFrom<rewards_calculator_results::Percent> for Percent {
    type Error = String;

    fn try_from(value: rewards_calculator_results::Percent) -> Result<Self, Self::Error> {
        Ok(Self(decimal_to_f64(value.get())?))
    }
}

#[derive(candid::CandidType, candid::Deserialize)]
pub struct DayUTC(String);

#[allow(deprecated)]
impl From<rewards_calculator_results::DayUTC> for DayUTC {
    fn from(value: rewards_calculator_results::DayUTC) -> Self {
        let secs = value.unix_ts_at_day_end() as i64 / 1_000_000_000;
        let nsecs = (value.unix_ts_at_day_end() % 1_000_000_000) as u32;

        let dd_mm_yyyy = DateTime::<Utc>::from_utc(
            chrono::NaiveDateTime::from_timestamp_opt(secs, nsecs).unwrap(),
            Utc,
        )
        .format("%d-%m-%Y")
        .to_string();

        Self(dd_mm_yyyy)
    }
}
