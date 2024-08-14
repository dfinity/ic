use icp_ledger::TimeStamp;

pub mod balance_book;
pub mod blocks;
pub mod blocks_access;
pub mod canister_access;
pub mod certification;
pub mod errors;
pub mod ledger_blocks_sync;
pub mod rosetta_block;

pub fn timestamp_to_iso8601(ts: TimeStamp) -> String {
    let secs = (ts.as_nanos_since_unix_epoch() / 1_000_000_000) as i64;
    let nsecs = (ts.as_nanos_since_unix_epoch() % 1_000_000_000) as u32;
    chrono::DateTime::from_timestamp(secs, nsecs)
        .unwrap()
        .to_rfc3339()
}

pub fn iso8601_to_timestamp(s: String) -> TimeStamp {
    let nanos = chrono::DateTime::<chrono::FixedOffset>::parse_from_rfc3339(&s)
        .unwrap_or_else(|e| panic!("Unable to parse timestamp from rfc3339 {}: {}", s, e))
        .with_timezone(&chrono::Utc)
        .timestamp_nanos_opt()
        .unwrap() as u64;
    TimeStamp::from_nanos_since_unix_epoch(nanos)
}

#[test]
fn test_iso8601_roundstrip() {
    // limit the test over a period that makes sense
    const MAX: u64 = 3000000000000000000;
    proptest::proptest!(|(nsecs in 0..MAX)| {
        let expected = TimeStamp::from_nanos_since_unix_epoch(nsecs);
        let iso8601_datetime = timestamp_to_iso8601(expected);
        let actual = iso8601_to_timestamp(iso8601_datetime.clone());
        proptest::prop_assert_eq!(expected, actual, "{}", iso8601_datetime)
    })
}
