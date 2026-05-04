use crate::Time;
use crate::time::{NANOS_PER_MILLI, NANOS_PER_SEC, TimeInstantiationError};
use assert_matches::assert_matches;
use std::time::SystemTime;

mod millis {
    use super::*;
    use crate::time::GENESIS;
    use std::time::Duration;

    #[test]
    fn should_convert_genesis_to_millis() {
        let genesis_millis = GENESIS.as_millis_since_unix_epoch();
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
        let sub_milli_offset = Duration::from_millis(1) - Duration::from_nanos(1);

        let result_in_millis = (GENESIS + sub_milli_offset).as_millis_since_unix_epoch();

        assert_eq!(result_in_millis, 1_620_328_630_000);
    }

    #[test]
    fn should_not_overflow() {
        let genesis_millis = Time::from_millis_since_unix_epoch(1_620_328_630_000);
        assert_matches!( genesis_millis, Ok(time) if time == GENESIS )
    }

    #[test]
    fn should_overflow_in_year_2554() {
        // Equals 18_446_744_073_709 ms since epoch
        // Corresponds to Sunday, 21 July 2554 23:34:33.709 (GMT)
        let max_millis = u64::MAX / NANOS_PER_MILLI;

        let result = Time::from_millis_since_unix_epoch(max_millis + 1);
        assert_matches!(result, Err(TimeInstantiationError::Overflow(_)));

        let result = Time::from_millis_since_unix_epoch(max_millis);
        assert_eq!(
            result,
            Ok(Time::from_nanos_since_unix_epoch(
                18_446_744_073_709_000_000
            ))
        );
    }
}

mod secs {
    use super::*;
    use crate::time::GENESIS;
    use std::time::Duration;

    #[test]
    fn should_convert_genesis_to_secs() {
        let genesis_secs = GENESIS.as_secs_since_unix_epoch();
        assert_eq!(genesis_secs, 1_620_328_630);
    }

    #[test]
    fn should_be_zero() {
        let less_than_one_sec =
            Time::from_duration(Duration::from_secs(1) - Duration::from_nanos(1));
        assert_eq!(less_than_one_sec.as_secs_since_unix_epoch(), 0);
    }

    #[test]
    fn should_ignore_sub_secs_precision() {
        let sub_sec_offset = Duration::from_secs(1) - Duration::from_nanos(1);

        let result_in_secs = (GENESIS + sub_sec_offset).as_secs_since_unix_epoch();

        assert_eq!(result_in_secs, 1_620_328_630);
    }

    #[test]
    fn should_not_overflow() {
        let genesis_secs = Time::from_secs_since_unix_epoch(1_620_328_630);
        assert_matches!( genesis_secs, Ok(time) if time == GENESIS )
    }

    #[test]
    fn should_overflow_in_year_2554() {
        // Equals 18_446_744_073 s since epoch
        // Corresponds to Sunday, 21 July 2554 23:34:33 (GMT)
        let max_secs = u64::MAX / NANOS_PER_SEC;

        let result = Time::from_secs_since_unix_epoch(max_secs + 1);
        assert_matches!(result, Err(TimeInstantiationError::Overflow(_)));

        let result = Time::from_secs_since_unix_epoch(max_secs);
        assert_eq!(
            result,
            Ok(Time::from_nanos_since_unix_epoch(
                18_446_744_073_000_000_000
            ))
        );
    }
}

#[test]
fn should_convert_from_system_time_and_back() {
    let system_time = SystemTime::now();
    let time: Time = system_time.try_into().unwrap();

    let system_time_nanos = system_time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let time_nanos = time.as_nanos_since_unix_epoch();
    assert_eq!(system_time_nanos, time_nanos);

    let back: SystemTime = time.into();
    assert_eq!(system_time, back);
}

mod coarse {
    use super::*;
    use crate::time::CoarseTime;

    const NANOS_PER_HALF_SEC: i64 = NANOS_PER_SEC as i64 / 2;

    /// Constructs a `Time` value from a number of seconds and a possibly negative number of nanoseconds.
    fn time_from(seconds: u64, nanos: i64) -> Time {
        assert!(nanos.abs() < NANOS_PER_SEC as i64);

        Time::from_nanos_since_unix_epoch(((seconds * NANOS_PER_SEC) as i64 + nanos) as u64)
    }

    #[test]
    fn coarse_time_floor() {
        // All times between `3s` and `4s-1ns` have a floor of `3s`.
        assert_eq!(3, CoarseTime::floor(time_from(3, 0)).0);
        assert_eq!(3, CoarseTime::floor(time_from(3, 1)).0);
        assert_eq!(3, CoarseTime::floor(time_from(3, NANOS_PER_HALF_SEC - 1)).0);
        assert_eq!(3, CoarseTime::floor(time_from(3, NANOS_PER_HALF_SEC)).0);
        assert_eq!(3, CoarseTime::floor(time_from(3, NANOS_PER_HALF_SEC + 1)).0);
        assert_eq!(3, CoarseTime::floor(time_from(4, -1)).0);

        assert_eq!(0, CoarseTime::floor(time_from(0, 0)).0);
        assert_eq!(0, CoarseTime::floor(time_from(0, 1)).0);
        assert_eq!(
            u32::MAX,
            CoarseTime::floor(Time::from_nanos_since_unix_epoch(u64::MAX)).0
        );
    }

    #[test]
    fn coarse_time_round() {
        // All times between `3s` and `3.5s` (exclusive) round to `3s`.
        assert_eq!(3, CoarseTime::round(time_from(3, 0)).0);
        assert_eq!(3, CoarseTime::round(time_from(3, 1)).0);
        assert_eq!(3, CoarseTime::round(time_from(3, NANOS_PER_HALF_SEC - 1)).0);
        // All times between `3.5s` and `4s-1ns` round to `4s`.
        assert_eq!(4, CoarseTime::round(time_from(3, NANOS_PER_HALF_SEC)).0);
        assert_eq!(4, CoarseTime::round(time_from(3, NANOS_PER_HALF_SEC + 1)).0);
        assert_eq!(4, CoarseTime::round(time_from(4, -1)).0);

        assert_eq!(0, CoarseTime::round(time_from(0, 0)).0);
        assert_eq!(0, CoarseTime::round(time_from(0, 1)).0);
        assert_eq!(
            u32::MAX,
            CoarseTime::round(Time::from_nanos_since_unix_epoch(u64::MAX)).0
        );
    }

    #[test]
    fn coarse_time_ceil() {
        // The ceiling of `3s` is `3s`.
        assert_eq!(3, CoarseTime::ceil(time_from(3, 0)).0);
        // All times between `3s+1ns` and `4s-1ns` have a ceiling of `4s`.
        assert_eq!(4, CoarseTime::ceil(time_from(3, 1)).0);
        assert_eq!(4, CoarseTime::ceil(time_from(3, NANOS_PER_HALF_SEC - 1)).0);
        assert_eq!(4, CoarseTime::ceil(time_from(3, NANOS_PER_HALF_SEC)).0);
        assert_eq!(4, CoarseTime::ceil(time_from(3, NANOS_PER_HALF_SEC + 1)).0);
        assert_eq!(4, CoarseTime::ceil(time_from(4, -1)).0);

        assert_eq!(0, CoarseTime::ceil(time_from(0, 0)).0);
        assert_eq!(1, CoarseTime::ceil(time_from(0, 1)).0);
        assert_eq!(
            u32::MAX,
            CoarseTime::ceil(Time::from_nanos_since_unix_epoch(u64::MAX)).0
        );
    }
}
