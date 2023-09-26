//! Implementation of functions for Matched Funding.

// TODO[NNS1-2619]: remove this
#![allow(dead_code)]
#![allow(unused)]

use ic_nervous_system_common::E8;
use ic_sns_swap::pb::v1::{LinearScalingCoefficient, NeuronsFundParticipationConstraints};

// TODO[NNS1-2619]
// use rust_decimal::Decimal;
// use rust_decimal_macros::dec;

/// This is a theoretical limit which should be smaller than any realistic amount of maturity
/// that practically needs to be reserved from the Neurons' Fund for a given SNS swap.
const MAX_THEORETICAL_NEURONS_FUND_PARTICIPATION_AMOUNT_ICP_E8S: u64 = 333_000 * E8;

/// An invertible function is a function that has an inverse.
///
/// Say we have an invertible function `f(x: u64) -> u64` and its inverse is `g(y: u64) -> u64`.
/// Then the equality `g(f(x)) = x` must hold for all `x` s.t. `g(f(x))` is defined.
///
/// Additionally, the equality `f(g(y)) = y` must hold for all `y` s.t. `f(g(y))` is defined.
pub trait InvertibleFunction {
    fn apply(&self, x: u64) -> f64;
    fn invert(&self, x: f64) -> Result<u64, String>;
}

pub struct SimpleLinearFunction {}

impl InvertibleFunction for SimpleLinearFunction {
    fn apply(&self, x: u64) -> f64 {
        x as f64
    }

    fn invert(&self, x: f64) -> Result<u64, String> {
        Ok(x.round() as u64)
    }
}

pub struct MatchedParticipationFunction {
    function: Box<dyn Fn(u64) -> f64>,
    params: NeuronsFundParticipationConstraints,
}

impl MatchedParticipationFunction {
    pub fn new(
        function: Box<dyn Fn(u64) -> f64>,
        params: NeuronsFundParticipationConstraints,
    ) -> Result<Self, String> {
        // TODO[NNS1-2619]: validate params
        Ok(Self { function, params })
    }

    fn find_interval(&self, x: u64) -> Option<LinearScalingCoefficient> {
        let mut i = 0_usize;
        let mut j = self.params.coefficient_intervals.len() - 1;
        while i <= j {
            let m = (i + j) / 2;
            let interval = &self.params.coefficient_intervals[m];
            let interval_from = interval.from_direct_participation_icp_e8s.unwrap(); // included
            let interval_to = interval.to_direct_participation_icp_e8s.unwrap();
            if interval_to <= x {
                // included, since x == interval[m].to ==> x \in interval[m+1]
                // ... [interval[m].from, interval[m].to) ... x ...
                i = m + 1;
            } else if x < interval_from {
                // exclused, since x == interval[m].from ==> x \in interval[m]
                // ... x ... [interval[m].from, interval[m].to) ...
                j = m - 1;
            } else {
                // interval_from <= x < interval_to
                // x \in interval[m]
                return Some(interval.clone());
            }
        }
        None
    }

    pub fn apply(&self, direct_participation_icp_e8s: u64) -> u64 {
        if direct_participation_icp_e8s
            < self
                .params
                .min_direct_participation_threshold_icp_e8s
                .unwrap()
        {
            println!("direct_participation_icp_e8s = {direct_participation_icp_e8s}");
            return 0;
        }

        // Check if this is a special case.
        {
            let intervals = &self.params.coefficient_intervals;
            assert!(
                !intervals.is_empty(),
                "There must be at least one interval."
            );
            // Special case A: direct_participation_icp_e8s is less than the first interval.
            if let Some(first_interval) = intervals.first() {
                if direct_participation_icp_e8s
                    < first_interval.from_direct_participation_icp_e8s.unwrap()
                {
                    // This should not happen in practice, as the first interval should contain 0.
                    return 0;
                }
            }
            // Special case B: direct_participation_icp_e8s is greated than the last interval.
            if let Some(last_interval) = intervals.last() {
                if last_interval.to_direct_participation_icp_e8s.unwrap()
                    <= direct_participation_icp_e8s
                {
                    return std::cmp::min(
                        self.params.max_neurons_fund_participation_icp_e8s.unwrap(),
                        MAX_THEORETICAL_NEURONS_FUND_PARTICIPATION_AMOUNT_ICP_E8S,
                    );
                }
            }
        }

        // Otherwise, direct_participation_icp_e8s must fall into one of the intervals.
        if let Some(LinearScalingCoefficient {
            slope_numerator: Some(slope_numerator),
            slope_denominator: Some(slope_denominator),
            intercept_icp_e8s: Some(intercept_icp_e8s),
            ..
        }) = self.find_interval(direct_participation_icp_e8s)
        {
            // Normal case:
            let ideal = (self.function)(direct_participation_icp_e8s);
            let effective = intercept_icp_e8s.saturating_add(
                (((slope_numerator as f64) * ideal) / (slope_denominator as f64)).round() as u64,
            );
            return std::cmp::min(
                effective,
                std::cmp::min(
                    self.params.max_neurons_fund_participation_icp_e8s.unwrap(),
                    MAX_THEORETICAL_NEURONS_FUND_PARTICIPATION_AMOUNT_ICP_E8S,
                ),
            );
        }

        unreachable!("Found a bug in MatchedParticipationFunction.find_interval");
    }
}

mod tests {
    use super::{InvertibleFunction, MatchedParticipationFunction, SimpleLinearFunction};
    use ic_nervous_system_common::E8;
    use ic_sns_swap::pb::v1::{LinearScalingCoefficient, NeuronsFundParticipationConstraints};

    #[test]
    fn test_simple_linear_function() {
        let f = SimpleLinearFunction {};
        let run_test_for_a = |x: u64| {
            let y = f.apply(x);
            let x1 = f.invert(y).unwrap();
            assert_eq!(x, x1);
        };
        let run_test_for_b = |y: f64| {
            let x = f.invert(y).unwrap();
            let y1 = f.apply(x);
            assert_eq!(y, y1);
        };
        run_test_for_a(0);
        run_test_for_a(77 * E8);
        run_test_for_a(888 * E8 + 123);
        run_test_for_a(9_999 * E8);

        run_test_for_b(0 as f64);
        run_test_for_b((77 * E8) as f64);
        run_test_for_b((888 * E8 + 123) as f64);
        run_test_for_b((9_999 * E8) as f64);
    }

    #[test]
    fn test_intervals() {
        let slope_denominator = 200_000 * E8;
        let max_neurons_fund_participation_icp_e8s = 95_000 * E8;
        let params = NeuronsFundParticipationConstraints {
            min_direct_participation_threshold_icp_e8s: Some(50 * E8),
            max_neurons_fund_participation_icp_e8s: Some(max_neurons_fund_participation_icp_e8s),
            coefficient_intervals: vec![
                LinearScalingCoefficient {
                    // Interval A
                    from_direct_participation_icp_e8s: Some(0),
                    to_direct_participation_icp_e8s: Some(100 * E8),
                    slope_numerator: Some(100_000 * E8),
                    slope_denominator: Some(slope_denominator),
                    intercept_icp_e8s: Some(111),
                },
                LinearScalingCoefficient {
                    // Interval B
                    from_direct_participation_icp_e8s: Some(100 * E8),
                    to_direct_participation_icp_e8s: Some(1_000 * E8),
                    slope_numerator: Some(120_000 * E8),
                    slope_denominator: Some(slope_denominator),
                    intercept_icp_e8s: Some(222),
                },
                LinearScalingCoefficient {
                    // Interval C
                    from_direct_participation_icp_e8s: Some(1_000 * E8),
                    to_direct_participation_icp_e8s: Some(10_000 * E8),
                    slope_numerator: Some(140_000 * E8),
                    slope_denominator: Some(slope_denominator),
                    intercept_icp_e8s: Some(333),
                },
                LinearScalingCoefficient {
                    // Interval D
                    from_direct_participation_icp_e8s: Some(10_000 * E8),
                    to_direct_participation_icp_e8s: Some(100_000 * E8),
                    slope_numerator: Some(160_000 * E8),
                    slope_denominator: Some(slope_denominator),
                    intercept_icp_e8s: Some(444),
                },
                LinearScalingCoefficient {
                    // Interval E
                    from_direct_participation_icp_e8s: Some(100_000 * E8),
                    to_direct_participation_icp_e8s: Some(1_000_000 * E8),
                    slope_numerator: Some(180_000 * E8),
                    slope_denominator: Some(slope_denominator),
                    intercept_icp_e8s: Some(555),
                },
            ],
        };
        let f = SimpleLinearFunction {};
        let g = MatchedParticipationFunction::new(Box::from(move |x| f.apply(x)), params).unwrap();
        // Below min_direct_participation_threshold_icp_e8s
        assert_eq!(g.apply(0), 0);
        // Falls into Interval A, thus we expect slope(0.5) * x + intercept_icp_e8s(111)
        assert_eq!(g.apply(90 * E8), 45 * E8 + 111);
        // Falls into Interval B, thus we expect slope(0.6) * x + intercept_icp_e8s(222)
        assert_eq!(g.apply(100 * E8), 60 * E8 + 222);
        // Falls into Interval C, thus we expect slope(0.7) * x + intercept_icp_e8s(333)
        assert_eq!(g.apply(5_000 * E8), 3_500 * E8 + 333);
        // Falls into Interval D, thus we expect slope(0.8) * x + intercept_icp_e8s(444)
        assert_eq!(g.apply(100_000 * E8 - 1), 80_000 * E8 - 1 + 444);
        // Falls into Interval D, thus we expect slope(0.9) * x + intercept_icp_e8s(555)
        assert_eq!(g.apply(100_000 * E8), 90_000 * E8 + 555);
        // Beyond the last interval
        assert_eq!(
            g.apply(1_000_000 * E8),
            max_neurons_fund_participation_icp_e8s
        );
        // Extremely high value
        assert_eq!(g.apply(u64::MAX), max_neurons_fund_participation_icp_e8s);
    }
}
