use super::*;
use serde::Serialize;

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
struct T {
    #[serde(default, with = "crate::serde::optional_time_of_day")]
    lunchtime: Option<GlobalTimeOfDay>,

    // This is here to work around an apparent bug in serde_yaml where if you
    // feed it an empty string, it will not return T { lunchtime: None }
    meaning_of_life: i32,
}

#[test]
fn test_round_trip() {
    fn assert_survives_round_trip(
        original_time_of_day_str: &str,
        expected_seconds_after_utc_midnight: u64,
        expected_formatted_str: &str,
    ) {
        let yaml = format!(
            "lunchtime: {}\nmeaning_of_life: 42\n",
            original_time_of_day_str
        );
        let t: T = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(
            t,
            T {
                lunchtime: Some(GlobalTimeOfDay {
                    seconds_after_utc_midnight: Some(expected_seconds_after_utc_midnight),
                }),
                meaning_of_life: 42,
            },
            "original_time_of_day_str = {:?}",
            original_time_of_day_str,
        );

        assert_eq!(
            serde_yaml::to_string(&t).unwrap(),
            format!(
                "lunchtime: {}\nmeaning_of_life: 42\n",
                expected_formatted_str
            ),
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
fn test_none() {
    // Case 1: lunchtime is explicitly null.
    let yaml = "lunchtime: null\nmeaning_of_life: 42\n";
    let t: T = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(
        t,
        T {
            lunchtime: None,
            meaning_of_life: 42,
        },
    );
    assert_eq!(serde_yaml::to_string(&t).unwrap(), yaml,);

    // Case 2: lunchtime is absent. This case reveals the bug mentioned earlier
    // in the comment above the meaning_of_life field.
    let t: T = serde_yaml::from_str("meaning_of_life: 42").unwrap();
    assert_eq!(
        t,
        T {
            lunchtime: None,
            meaning_of_life: 42,
        },
    );
}
