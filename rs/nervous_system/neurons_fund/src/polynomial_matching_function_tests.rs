use super::*;
use crate::{DeserializableFunction, SerializableFunction, E8};
use assert_matches::assert_matches;
use ic_nervous_system_common::WIDE_RANGE_OF_U64_VALUES;
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
    let f = PolynomialMatchingFunction::from_persistent_data(PERSISTENT_DATA_FOR_TESTS.clone())
        .unwrap();
    println!("Testing {:#?} ...", f);
    let assert_close_enough = |arg_icp_e8s: u64, expected_icp: Decimal| {
        let observed_icp = f.apply(arg_icp_e8s).unwrap();
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
fn polynomial_matching_function_viability_test() {
    let neurons_fund_participation_limits = NeuronsFundParticipationLimits {
        max_theoretical_neurons_fund_participation_amount_icp: dec!(333_000.0),
        contribution_threshold_icp: dec!(75_000.0),
        one_third_participation_milestone_icp: dec!(225_000.0),
        full_participation_milestone_icp: dec!(375_000.0),
    };
    for total_maturity_equivalent_icp_e8s in &*WIDE_RANGE_OF_U64_VALUES {
        // Check that the function can be created.
        let f = assert_matches!(PolynomialMatchingFunction::new(
            *total_maturity_equivalent_icp_e8s,
            neurons_fund_participation_limits,
            true
        ), Ok(f) => f);
        // Check that the function can be serialized / deserialized.
        let f1: Box<PolynomialMatchingFunction> = assert_matches!(
            DeserializableFunction::from_repr(&f.serialize()),
            Ok(f_repr) => f_repr
        );
        // Check that serialization / deserialization cycle is idempotent.
        assert_eq!(*f1, f);
        // Test that the function can be plotted.
        let _plot = f.plot(NonZeroU64::try_from(1_000).unwrap()).unwrap();
        // Check that the maximum value is defined.
        let _max_argument_icp_e8s = assert_matches!(f.max_argument_icp_e8s(), Ok(max_argument_icp_e8s) => max_argument_icp_e8s);
        // Test that it is safe to apply the function over a broad range of values.
        for x_icp_e8s in &*WIDE_RANGE_OF_U64_VALUES {
            // Check that the function can be applied to `x_icp_e8s`.
            let y_icp = assert_matches!(f.apply(*x_icp_e8s), Ok(y_icp) => y_icp);
            // Check that the result can be rescaled back to ICP e8s.
            assert_matches!(rescale_to_icp_e8s(y_icp), Ok(_));
            // Check that the result can be inverted.
            let x1_icp_e8s = assert_matches!(f.invert(y_icp), Ok(x1_icp_e8s) => x1_icp_e8s);
            assert_eq!(f.apply(x1_icp_e8s), f.apply(*x_icp_e8s));
        }
    }
}

#[test]
fn plot_test() {
    let f = PolynomialMatchingFunction::from_persistent_data(PERSISTENT_DATA_FOR_TESTS.clone())
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
        let y_icp = f.apply(x_icp_e8s).unwrap();
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
