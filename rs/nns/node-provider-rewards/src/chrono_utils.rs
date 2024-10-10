use chrono::{Duration, NaiveDateTime, TimeZone, Utc};
use trustworthy_node_metrics_types::types::TimestampNanos;

#[derive(Clone)]
pub struct DateTimeRange {
    start_dt: NaiveDateTime,
    end_dt: NaiveDateTime,
}

impl DateTimeRange {
    pub fn new(from_ts: TimestampNanos, to_ts: TimestampNanos) -> Self {
        let start_date = Utc.timestamp_nanos(from_ts as i64).date_naive().and_hms_opt(0, 0, 0).unwrap();
        let end_date = Utc.timestamp_nanos(to_ts as i64).date_naive().and_hms_opt(0, 0, 0).unwrap() + Duration::days(1);

        Self {
            start_dt: start_date,
            end_dt: end_date,
        }
    }

    pub fn days_between(&self) -> u64 {
        (self.end_dt - self.start_dt).num_days() as u64
    }

    pub fn start_timestamp_nanos(&self) -> TimestampNanos {
        self.start_dt.and_utc().timestamp_nanos_opt().unwrap() as u64
    }

    pub fn end_timestamp_nanos(&self) -> TimestampNanos {
        self.end_dt.and_utc().timestamp_nanos_opt().unwrap() as u64
    }
}
