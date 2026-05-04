use super::*;
use crate::parse_time_of_day;
use serde::Serialize;

#[test]
fn test_round_trip() {
    fn assert_survives_round_trip(
        original_time_of_day_str: &str,
        expected_seconds_after_utc_midnight: u64,
        expected_formatted_str: &str,
    ) {
        #[derive(Eq, PartialEq, Debug, Deserialize, Serialize)]
        struct T {
            #[serde(with = "crate::serde::time_of_day")]
            lunchtime: GlobalTimeOfDay,
        }

        let yaml = format!("lunchtime: {original_time_of_day_str}");
        let t: T = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(
            t,
            T {
                lunchtime: GlobalTimeOfDay {
                    seconds_after_utc_midnight: Some(expected_seconds_after_utc_midnight),
                }
            },
            "original_time_of_day_str = {original_time_of_day_str:?}",
        );

        assert_eq!(
            serde_yaml::to_string(&t).unwrap(),
            format!("lunchtime: {expected_formatted_str}\n"),
            "original_time_of_day_str = {:?}",
            original_time_of_day_str,
        );
    }

    assert_survives_round_trip("00:00 UTC", 0, "00:00 UTC");
    assert_survives_round_trip("00:01 UTC", 60, "00:01 UTC");
    assert_survives_round_trip("00:10 UTC", 600, "00:10 UTC");
    assert_survives_round_trip("01:00 UTC", 3600, "01:00 UTC");
    assert_survives_round_trip("20:00 UTC", 72000, "20:00 UTC");
    assert_survives_round_trip("20:01 UTC", 72060, "20:01 UTC");
    assert_survives_round_trip("20:30 UTC", 73800, "20:30 UTC");
}

#[test]
fn test_parse_failure_no_timestamp() {
    parse_time_of_day("10:10").unwrap_err();
}

#[test]
fn test_parse_failure_timestamp_wrong_timezone() {
    parse_time_of_day("10:10 EST").unwrap_err();
}

#[test]
fn test_parse_failure_too_many_minutes() {
    parse_time_of_day("10:90 EST").unwrap_err();
    parse_time_of_day("10:300 EST").unwrap_err();
}

#[test]
fn test_parse_failure_too_many_hours() {
    parse_time_of_day("30:30 EST").unwrap_err();
    parse_time_of_day("100:30 EST").unwrap_err();
}

// TODO(NNS1-2295): Support this
#[test]
fn test_parse_failure_seconds() {
    parse_time_of_day("10:30:30 EST").unwrap_err();
}
