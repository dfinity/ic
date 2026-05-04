use super::*;

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
