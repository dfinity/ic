#![allow(clippy::reversed_empty_ranges)]

use ic_nervous_system_linear_map::LinearMap;
use rust_decimal::Decimal;

#[test]
fn test_increasing_linear_map() {
    let map = LinearMap::new(5..6, 100..200);

    // Look at the extrema (this should be a no-brainer).
    assert_eq!(map.apply(5), Decimal::from(100));
    assert_eq!(map.apply(6), Decimal::from(200));

    // Look at the middle.
    assert_eq!(
        map.apply(Decimal::try_from(5.25).unwrap()),
        Decimal::from(125)
    );
    assert_eq!(
        map.apply(Decimal::try_from(5.50).unwrap()),
        Decimal::from(150)
    );
    assert_eq!(
        map.apply(Decimal::try_from(5.75).unwrap()),
        Decimal::from(175)
    );

    // Look outside (this should still work).
    assert_eq!(map.apply(4), Decimal::from(0));
    assert_eq!(map.apply(3), Decimal::from(-100));
    assert_eq!(map.apply(8), Decimal::from(400));

    // Scan up.
    for i in 0..=10 {
        assert_eq!(map.apply(i + 5), Decimal::from(100 * i + 100));
    }

    // Scan down.
    for i in 0..=10 {
        assert_eq!(map.apply(-i + 5), Decimal::from(-100 * i + 100));
    }
}

#[test]
fn test_decreasing_linear_map() {
    let map = LinearMap::new(500..600, 2000..1000);

    // Look at the extrema (this should be a no-brainer).
    assert_eq!(map.apply(500), Decimal::from(2000));
    assert_eq!(map.apply(600), Decimal::from(1000));

    // Look at the middle.
    assert_eq!(map.apply(525), Decimal::from(1750));
    assert_eq!(map.apply(550), Decimal::from(1500));
    assert_eq!(map.apply(575), Decimal::from(1250));

    // Look outside (this should still work).
    assert_eq!(map.apply(750), Decimal::from(-500));
    assert_eq!(map.apply(300), Decimal::from(4000));

    // Scan up.
    for i in 0..=12 {
        assert_eq!(map.apply(25 * i + 500), Decimal::from(-250 * i + 2000));
    }

    // Scan down.
    for i in 0..=12 {
        assert_eq!(map.apply(-25 * i + 500), Decimal::from(250 * i + 2000));
    }
}
