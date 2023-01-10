use crate::time::{TimeInstantiationError, NANOS_PER_MILLI};
use crate::Time;
use assert_matches::assert_matches;

mod millis {
    use super::*;
    use std::time::Duration;

    #[test]
    fn should_convert_genesis_to_millis() {
        let genesis = Time::from_nanos_since_unix_epoch(1_620_328_630_000_000_000);
        let genesis_millis = genesis.as_millis_since_unix_epoch();
        assert_eq!(genesis_millis, 1_620_328_630_000);
    }

    #[test]
    fn should_be_zero() {
        let less_than_one_milli =
            Time::from_duration(Duration::from_millis(1) - Duration::from_nanos(1));
        assert_eq!(less_than_one_milli.as_millis_since_unix_epoch(), 0);
    }

    #[test]
    fn should_ignore_sub_millis_precision() {
        let genesis = Time::from_nanos_since_unix_epoch(1_620_328_630_000_000_000);
        let sub_milli_offset = Duration::from_millis(1) - Duration::from_nanos(1);

        let result_in_millis = (genesis + sub_milli_offset).as_millis_since_unix_epoch();

        assert_eq!(result_in_millis, 1_620_328_630_000);
    }

    #[test]
    fn should_not_overflow() {
        let genesis = Time::from_millis_since_unix_epoch(1_620_328_630_000);
        assert_matches!(
            genesis,
            Ok(time) if time == Time::from_nanos_since_unix_epoch(1_620_328_630_000_000_000)
        )
    }

    #[test]
    fn should_overflow_in_year_2554() {
        // Equals 18_446_744_073_709 ms since epoch
        // Corresponds to Sunday, 21 July 2554 23:34:33.709 (GMT)
        let max_millis = u64::MAX / NANOS_PER_MILLI;

        let result = Time::from_millis_since_unix_epoch(max_millis + 1);
        assert_matches!(result, Err(TimeInstantiationError::Overflow(_)));

        let result = Time::from_millis_since_unix_epoch(max_millis);
        assert_matches!(result, Ok(time) if time == Time::from_nanos_since_unix_epoch(18_446_744_073_709_000_000));
    }
}
