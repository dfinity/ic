use super::*;

#[test]
fn test_wide_range_of_u64_values() {
    assert!(WIDE_RANGE_OF_U64_VALUES.contains(&0));
    assert!(WIDE_RANGE_OF_U64_VALUES.contains(&1));
    assert!(WIDE_RANGE_OF_U64_VALUES.contains(&8));
    assert!(WIDE_RANGE_OF_U64_VALUES.contains(&43));
    assert!(WIDE_RANGE_OF_U64_VALUES.contains(&57));
    assert!(WIDE_RANGE_OF_U64_VALUES.contains(&u64::MAX));
}

#[test]
fn test_e8s_to_tokens() {
    for e8s in &*WIDE_RANGE_OF_U64_VALUES {
        let e8s = *e8s;
        assert_eq!(
            denominations_to_tokens(e8s, E8),
            Some(Decimal::from(e8s) / Decimal::from(E8)),
            "{}",
            e8s
        );
    }
}
