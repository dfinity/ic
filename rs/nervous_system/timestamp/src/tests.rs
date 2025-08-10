use super::*;

#[test]
fn test_format_timestamp() {
    for (expected, timestamp_seconds) in [
        (Some("1970-01-01 00:00:00 UTC"), 0),
        (Some("2024-11-29 16:14:10 UTC"), 1732896850),
        (Some("2038-01-19 03:14:07 UTC"), i32::MAX as u64),
        (Some("4571-09-24 08:52:47 UTC"), 82102668767),
        (Some("9999-12-31 23:59:59 UTC"), 253402300799),
        (None, 253402300800),
        (None, i64::MAX as u64),
        (None, u64::MAX),
    ] {
        let observed_opt = format_timestamp(timestamp_seconds);
        assert_eq!(
            observed_opt,
            expected.map(|s| s.to_string()),
            "unexpected result from format_timestamp({})",
            timestamp_seconds,
        );

        let observed_str = format_timestamp_for_humans(timestamp_seconds);
        if let Some(expected) = expected {
            assert_eq!(
                observed_str,
                expected.to_string(),
                "unexpected result from format_timestamp_for_humans({})",
                timestamp_seconds,
            );
        } else {
            let expected_fallback = format!("timestamp {} seconds", timestamp_seconds);
            assert_eq!(
                observed_str, expected_fallback,
                "unexpected result from format_timestamp_for_humans({})",
                timestamp_seconds,
            );
        }
    }
}
