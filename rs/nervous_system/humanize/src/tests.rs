use super::*;

#[test]
fn test_parse_tokens() {
    assert_eq!(
        parse_tokens("1e8s"),
        Ok(nervous_system_pb::Tokens { e8s: Some(1) }),
    );
    assert_eq!(
        parse_tokens("1 token"),
        Ok(nervous_system_pb::Tokens {
            e8s: Some(100_000_000)
        }),
    );
    assert_eq!(
        parse_tokens("1_.23_4_tokens"),
        Ok(nervous_system_pb::Tokens {
            e8s: Some(123_400_000)
        }),
    );
    assert_eq!(
        parse_tokens("_123_456_789_e8s"),
        Ok(nervous_system_pb::Tokens {
            e8s: Some(123456789)
        }),
    );
}

#[test]
fn test_parse_percentage() {
    assert_eq!(
        parse_percentage("0%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(0)
        }),
    );
    assert_eq!(
        parse_percentage("1%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(100)
        }),
    );
    assert_eq!(
        parse_percentage("1.0%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(100)
        }),
    );
    assert_eq!(
        parse_percentage("1.00%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(100)
        }),
    );
    assert_eq!(
        parse_percentage("1.2%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(120)
        }),
    );
    assert_eq!(
        parse_percentage("1.23%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(123)
        }),
    );
    assert_eq!(
        parse_percentage("0.1%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(10)
        }),
    );
    assert_eq!(
        parse_percentage("0.12%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(12)
        }),
    );
    assert_eq!(
        parse_percentage("0.07%"),
        Ok(nervous_system_pb::Percentage {
            basis_points: Some(7)
        }),
    );

    // Dot must be surrounded.
    let result = parse_percentage("0.%");
    assert!(result.is_err(), "{result:?}");

    let result = parse_percentage(".1%");
    assert!(result.is_err(), "{result:?}");

    // Too many decimal places.
    let result = parse_percentage("0.009%");
    assert!(result.is_err(), "{result:?}");

    // Percent sign required.
    let result = parse_percentage("1.0");
    assert!(result.is_err(), "{result:?}");
}

#[test]
fn test_shift_decimal_right() {
    assert_eq!(shift_decimal_right(0, 0).unwrap(), 0,);
    assert_eq!(shift_decimal_right(0, 5).unwrap(), 0,);

    assert_eq!(shift_decimal_right(1, 0).unwrap(), 1,);
    assert_eq!(shift_decimal_right(1, 1).unwrap(), 10,);
    assert_eq!(shift_decimal_right(1, 2).unwrap(), 100,);

    assert_eq!(shift_decimal_right(23, 2).unwrap(), 2300,);
}

#[test]
fn test_group_digits() {
    assert_eq!(group_digits(0), "0".to_string());
    assert_eq!(group_digits(1), "1".to_string());
    assert_eq!(group_digits(99), "99".to_string());
    assert_eq!(group_digits(999), "999".to_string());
    assert_eq!(group_digits(1_000), "1_000".to_string());
    assert_eq!(group_digits(123_456), "123_456".to_string());
    assert_eq!(group_digits(1_234_567), "1_234_567".to_string());
}
