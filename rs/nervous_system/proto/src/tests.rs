use super::*;

#[test]
fn test_global_time_of_day_from_hh_mm_accepts_all_valid_hours_and_minutes() {
    for hh in 0..24 {
        for mm in 0..60 {
            let time_of_day = GlobalTimeOfDay::from_hh_mm(hh, mm).unwrap();
            assert_eq!(time_of_day.to_hh_mm(), Some((hh, mm)));
        }
    }
}

#[test]
fn test_global_time_of_day_from_hh_mm_rejects_invalid_hours_and_minutes() {
    for hh in [0, 24, 25, u64::MAX] {
        for mm in [0, 60, 61, u64::MAX] {
            let is_valid = hh < 24 && mm < 60;
            if is_valid {
                continue;
            }

            GlobalTimeOfDay::from_hh_mm(hh, mm).unwrap_err();
        }
    }
}

#[test]
fn test_convert_decimal() {
    let original = Decimal::try_from(1.25).unwrap();
    assert_eq!(
        DecimalPb::from(original),
        DecimalPb {
            human_readable: Some("1.25".to_string()),
        },
    );

    assert_eq!(Decimal::try_from(DecimalPb::from(original)), Ok(original));

    for float in [0.0, -1.0, 1.0, 123.456] {
        let original = Decimal::try_from(float).unwrap();

        assert_eq!(
            DecimalPb::from(original),
            DecimalPb {
                human_readable: Some(float.to_string()),
            },
        );

        assert_eq!(Decimal::try_from(DecimalPb::from(original)), Ok(original));
    }
}
