use super::*;
use serde::Serialize;

#[test]
fn test_round_trip() {
    fn assert_survives_round_trip(
        original_duration_str: &str,
        expected_seconds: u64,
        expected_formatted_str: &str,
    ) {
        #[derive(Eq, PartialEq, Debug, Deserialize, Serialize)]
        struct T {
            #[serde(with = "crate::serde::duration")]
            duration: Duration,
        }

        let yaml = format!("duration: {original_duration_str}");
        let t: T = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(
            t,
            T {
                duration: Duration {
                    seconds: Some(expected_seconds),
                }
            },
            "original_duration_str = {original_duration_str:?}",
        );

        assert_eq!(
            serde_yaml::to_string(&t).unwrap(),
            format!("duration: {expected_formatted_str}\n"),
            "original_duration_str = {:?}",
            original_duration_str,
        );
    }

    assert_survives_round_trip("1 hour", 3600, "1h");
    assert_survives_round_trip("1h 2m 3s", 3723, "1h 2m 3s");
    assert_survives_round_trip("2 weeks", 2 * 7 * 24 * 60 * 60, "14days");
    assert_survives_round_trip("8 years", (8 * 365 + 2) * 24 * 60 * 60, "8years");
}
