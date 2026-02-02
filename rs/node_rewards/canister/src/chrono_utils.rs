use chrono::NaiveDate;

pub fn first_unix_timestamp_nanoseconds(naive_date: &NaiveDate) -> u64 {
    naive_date
        .and_hms_nano_opt(0, 0, 0, 1)
        .unwrap()
        .and_utc()
        .timestamp_nanos_opt()
        .unwrap() as u64
}

pub fn last_unix_timestamp_nanoseconds(naive_date: &NaiveDate) -> u64 {
    naive_date
        .and_hms_nano_opt(23, 59, 59, 999_999_999)
        .unwrap()
        .and_utc()
        .timestamp_nanos_opt()
        .unwrap() as u64
}

#[cfg(test)]
pub fn to_native_date(date: &str) -> NaiveDate {
    NaiveDate::parse_from_str(date, "%Y-%m-%d").unwrap()
}
