pub mod monthly_rewards;
pub mod provider_rewards_calculation;
pub mod providers_rewards;

use chrono::{DateTime, Datelike, NaiveDate};
use std::fmt::Display;

// These are API-facing types with all fields wrapped in `Option`
// to ensure deserialization always works
// in the future without breaking clients that consume the API.
#[derive(
    PartialOrd, Ord, Eq, candid::CandidType, candid::Deserialize, Clone, Copy, PartialEq, Debug,
)]
pub struct DayUtc {
    pub day: Option<u32>,
    pub month: Option<u32>,
    pub year: Option<u32>,
}

impl Display for DayUtc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}-{}-{} UTC",
            self.year.expect("Year is missing"),
            self.month.expect("Month is missing"),
            self.day.expect("Day is missing")
        )
    }
}

impl From<NaiveDate> for DayUtc {
    fn from(value: NaiveDate) -> Self {
        Self {
            day: Some(value.day()),
            month: Some(value.month()),
            year: Some(value.year() as u32),
        }
    }
}

impl TryFrom<DayUtc> for NaiveDate {
    type Error = String;

    fn try_from(value: DayUtc) -> Result<Self, Self::Error> {
        NaiveDate::from_ymd_opt(
            value.year.expect("Year is missing") as i32,
            value.month.expect("Month is missing"),
            value.day.expect("Day is missing"),
        )
        .ok_or(format!("Invalid date: {:?}", value))
    }
}

impl DayUtc {
    pub fn from_unix_timestamp_nanoseconds(value: u64) -> Self {
        let naive_date = DateTime::from_timestamp_nanos(value as i64).date_naive();
        DayUtc::from(naive_date)
    }
    pub fn from_unix_timestamp_seconds(value: u64) -> Self {
        let naive_date = DateTime::from_timestamp(value as i64, 0)
            .unwrap()
            .date_naive();
        DayUtc::from(naive_date)
    }
}
