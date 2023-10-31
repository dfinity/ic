use super::{
    InvertibleFunction, NonDecreasingFunction, PolynomialMatchingFunction,
    PolynomialMatchingFunctionPersistentData,
};
use crate::E8;
use assert_matches::assert_matches;
use lazy_static::lazy_static;
use rust_decimal::Decimal;
use rust_decimal_macros::dec;
use std::num::NonZeroU64;

const ERROR_TOLERANCE_ICP: Decimal = dec!(0.05);

lazy_static! {
    static ref PERSISTENT_DATA_FOR_TESTS: PolynomialMatchingFunctionPersistentData =
        PolynomialMatchingFunctionPersistentData {
            t_1: dec!(33.333333333333336),
            t_2: dec!(100.0),
            t_3: dec!(166.66666666666666),
            t_4: dec!(520.0),
            cap: dec!(260.0),
        };
}

#[test]
fn known_values_test() {
    let f = PolynomialMatchingFunction::from_persistant_data(PERSISTENT_DATA_FOR_TESTS.clone())
        .unwrap();
    println!("Testing {:#?} ...", f);
    let assert_close_enough = |arg_icp_e8s: u64, expected_icp: Decimal| {
        let observed_icp = f.apply_unchecked(arg_icp_e8s);
        assert!(
            (observed_icp - expected_icp).abs() <= ERROR_TOLERANCE_ICP,
            "Expected f({}) = {} but observed {} (tolerance = {})",
            arg_icp_e8s,
            expected_icp,
            observed_icp,
            ERROR_TOLERANCE_ICP,
        );
    };
    assert_close_enough(33 * E8, dec!(0));
    assert_close_enough(100 * E8, dec!(50));
    assert_close_enough(167 * E8, dec!(167));
    assert_close_enough(520 * E8, dec!(260));
}

#[test]
fn plot_test() {
    let f = PolynomialMatchingFunction::from_persistant_data(PERSISTENT_DATA_FOR_TESTS.clone())
        .unwrap();
    println!("Testing {:#?} ...", f);
    println!(
        "{}",
        f.plot(NonZeroU64::try_from(50).unwrap())
            .map(|plot| format!("{:?}", plot))
            .unwrap_or_else(|e| e)
    );
    for x in 0..=600 {
        let x_icp_e8s = x * E8;
        let y_icp = f.apply_unchecked(x_icp_e8s);
        if x_icp_e8s < 34 * E8 {
            assert_eq!(y_icp, dec!(0));
            continue;
        }
        if x_icp_e8s > 519 * E8 {
            assert_eq!(y_icp, dec!(260));
            continue;
        }
        let x1_icp_e8s = f.invert(y_icp);
        let x1_icp_e8s = assert_matches!(
            x1_icp_e8s, Ok(x1_icp_e8s) => x1_icp_e8s
        );
        assert!(
            x1_icp_e8s.abs_diff(x_icp_e8s) <= 1,
            "Inverted value {} is further away from the expected value {} than the error \
            tolerance 1_u64",
            x1_icp_e8s,
            x_icp_e8s,
        );
    }
}
