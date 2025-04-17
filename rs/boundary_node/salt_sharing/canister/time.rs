use std::time::Duration;

use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

fn next_month_date(current_time: OffsetDateTime) -> OffsetDateTime {
    // Get the current year, month, and day.
    let year = current_time.year();
    let month = current_time.month();

    // Calculate the next month and year.
    let (next_month, next_year) = if month == Month::December {
        (Month::January, year + 1)
    } else {
        (month.next(), year)
    };

    // Create the first moment of the next month.
    PrimitiveDateTime::new(
        Date::from_calendar_date(next_year, next_month, 1).expect("Invalid date"),
        Time::MIDNIGHT,
    )
    .assume_utc()
}

pub fn delay_till_next_month(current_time_ns: u64) -> Duration {
    let current_time = OffsetDateTime::from_unix_timestamp_nanos(current_time_ns as i128)
        .expect("Invalid current_time_ns value");
    let next_month = next_month_date(current_time);
    (next_month - current_time).unsigned_abs()
}

#[cfg(test)]
mod tests {
    use time::{Date, UtcOffset};

    use super::*;

    #[test]
    fn test_delay_till_next_month() {
        let minute_sec = 60;
        let hour_sec = minute_sec * 60;
        let day_sec = hour_sec * 24;

        // 27.02.2024 11:30 UTC (leap year) -> delay 2 days, 12 hours, 30 mins
        let from_dt = OffsetDateTime::new_in_offset(
            Date::from_calendar_date(2024, Month::February, 27).unwrap(),
            Time::from_hms_nano(11, 30, 0, 0).unwrap(),
            UtcOffset::from_hms(0, 0, 0).unwrap(),
        );
        let time = from_dt.unix_timestamp_nanos() as u64;
        let delay = delay_till_next_month(time);
        assert_eq!(
            delay,
            Duration::from_secs(2 * day_sec + 12 * hour_sec + 30 * minute_sec)
        );

        // 27.02.2025 11:30 UTC (non-leap year) -> delay 1 day, 12 hours, 30 mins
        let from_dt = OffsetDateTime::new_in_offset(
            Date::from_calendar_date(2025, Month::February, 27).unwrap(),
            Time::from_hms_nano(11, 30, 0, 0).unwrap(),
            UtcOffset::from_hms(0, 0, 0).unwrap(),
        );
        let time = from_dt.unix_timestamp_nanos() as u64;
        let delay = delay_till_next_month(time);
        assert_eq!(
            delay,
            Duration::from_secs(day_sec + 12 * hour_sec + 30 * minute_sec)
        );

        // 27.12.2024 11:35 UTC (December-January) -> delay 4 days, 12 hours, 25 mins
        let from_dt = OffsetDateTime::new_in_offset(
            Date::from_calendar_date(2024, Month::December, 27).unwrap(),
            Time::from_hms_nano(11, 35, 0, 0).unwrap(),
            UtcOffset::from_hms(0, 0, 0).unwrap(),
        );
        let time = from_dt.unix_timestamp_nanos() as u64;
        let delay = delay_till_next_month(time);
        assert_eq!(
            delay,
            Duration::from_secs(4 * day_sec + 12 * hour_sec + 25 * minute_sec)
        );
        // Verify that the date after delay is exactly the start of next month
        let time_after_delay_ns = time + delay.as_nanos() as u64;
        let dt_after_delay =
            OffsetDateTime::from_unix_timestamp_nanos(time_after_delay_ns as i128).unwrap();
        let expected_dt = OffsetDateTime::new_in_offset(
            Date::from_calendar_date(2025, Month::January, 1).unwrap(),
            Time::from_hms_nano(0, 0, 0, 0).unwrap(),
            UtcOffset::from_hms(0, 0, 0).unwrap(),
        );
        assert_eq!(dt_after_delay, expected_dt);
    }
}
