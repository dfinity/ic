//! Implementation of functions for Matched Funding.

// TODO[NNS1-2619]: remove this
#![allow(dead_code)]
#![allow(unused)]

use ic_nervous_system_common::E8;
use ic_sns_swap::pb::v1::{LinearScalingCoefficient, NeuronsFundParticipationConstraints};
use rust_decimal::{
    prelude::{FromPrimitive, ToPrimitive},
    Decimal, RoundingStrategy,
};
use rust_decimal_macros::dec;

/// This is a theoretical limit which should be smaller than any realistic amount of maturity
/// that practically needs to be reserved from the Neurons' Fund for a given SNS swap.
pub const MAX_THEORETICAL_NEURONS_FUND_PARTICIPATION_AMOUNT_ICP_E8S: u64 = 333_000 * E8;

// The maximum number of intervals for scaling ideal Neurons' Fund participation down to effective
// participation. Theoretically, this number should be greater than double the number of neurons
// participating in the Neurons' Fund. Although the currently chosen value is quite high, it is
// still significantly smaller than `usize::MAX`, allowing to reject an misformed
// SnsInitPayload.coefficient_intervals structure with obviously too many elements.
const MAX_LINEAR_SCALING_COEFFICIENT_VEC_LEN: usize = 100_000;

/// The implmentation of `Decimal::from_u64` cannot fail.
pub fn u64_to_dec(x: u64) -> Decimal {
    Decimal::from_u64(x).unwrap()
}

/// The canonical converter from (non-negative) `Decimal` to `u64`.
pub fn dec_to_u64(x: Decimal) -> Result<u64, String> {
    if x.is_sign_negative() {
        return Err(format!("Cannot convert negative value {:?} to u64.", x));
    }
    // The same could be achieved via `x.round()`, but we opt for verbosity.
    let x = x.round_dp_with_strategy(0, RoundingStrategy::MidpointNearestEven);
    // We already checked that 0 <= x; the only reason `to_u64` can fail at this point is overflow.
    Decimal::to_u64(&x)
        .ok_or_else(|| format!("Overflow while trying to convert value {:?} to u64.", x))
}

#[derive(Debug)]
pub enum LinearScalingCoefficientValidationError {
    // All fields are mandatory.
    UnspecifiedField(String),
    EmptyInterval {
        from_direct_participation_icp_e8s: u64,
        to_direct_participation_icp_e8s: u64,
    },
    DenominatorIsZero,
    // The slope should be between 0.0 and 1.0.
    NumeratorGreaterThanDenominator {
        slope_numerator: u64,
        slope_denominator: u64,
    },
}

impl ToString for LinearScalingCoefficientValidationError {
    fn to_string(&self) -> String {
        let prefix = "LinearScalingCoefficientValidationError: ";
        match self {
            Self::UnspecifiedField(field_name) => {
                format!("{}Field `{}` must be specified.", prefix, field_name)
            }
            Self::EmptyInterval {
                from_direct_participation_icp_e8s,
                to_direct_participation_icp_e8s,
            } => {
                format!(
                    "{}from_direct_participation_icp_e8s ({}) must be strictly less that \
                    to_direct_participation_icp_e8s ({})).",
                    prefix, from_direct_participation_icp_e8s, to_direct_participation_icp_e8s,
                )
            }
            Self::DenominatorIsZero => {
                format!("{}slope_denominator must not equal zero.", prefix)
            }
            Self::NumeratorGreaterThanDenominator {
                slope_numerator,
                slope_denominator,
            } => {
                format!(
                    "{}slope_numerator ({}) must be less than or equal \
                    slope_denominator ({})",
                    prefix, slope_numerator, slope_denominator,
                )
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct ValidatedLinearScalingCoefficient {
    pub from_direct_participation_icp_e8s: u64,
    pub to_direct_participation_icp_e8s: u64,
    pub slope_numerator: u64,
    pub slope_denominator: u64,
    pub intercept_icp_e8s: u64,
}

impl From<ValidatedLinearScalingCoefficient> for LinearScalingCoefficient {
    fn from(value: ValidatedLinearScalingCoefficient) -> Self {
        Self {
            from_direct_participation_icp_e8s: Some(value.from_direct_participation_icp_e8s),
            to_direct_participation_icp_e8s: Some(value.to_direct_participation_icp_e8s),
            slope_numerator: Some(value.slope_numerator),
            slope_denominator: Some(value.slope_denominator),
            intercept_icp_e8s: Some(value.intercept_icp_e8s),
        }
    }
}

impl TryFrom<LinearScalingCoefficient> for ValidatedLinearScalingCoefficient {
    type Error = LinearScalingCoefficientValidationError;

    fn try_from(value: LinearScalingCoefficient) -> Result<Self, Self::Error> {
        let from_direct_participation_icp_e8s =
            value.from_direct_participation_icp_e8s.ok_or_else(|| {
                LinearScalingCoefficientValidationError::UnspecifiedField(
                    "from_direct_participation_icp_e8s".to_string(),
                )
            })?;
        let to_direct_participation_icp_e8s =
            value.to_direct_participation_icp_e8s.ok_or_else(|| {
                LinearScalingCoefficientValidationError::UnspecifiedField(
                    "to_direct_participation_icp_e8s".to_string(),
                )
            })?;
        let slope_numerator = value.slope_numerator.ok_or_else(|| {
            LinearScalingCoefficientValidationError::UnspecifiedField("slope_numerator".to_string())
        })?;
        let slope_denominator = value.slope_denominator.ok_or_else(|| {
            LinearScalingCoefficientValidationError::UnspecifiedField(
                "slope_denominator".to_string(),
            )
        })?;
        // Currently we only check that `intercept_icp_e8s` is specified, so the actual field value
        // is unchecked.
        let intercept_icp_e8s = value.intercept_icp_e8s.ok_or_else(|| {
            LinearScalingCoefficientValidationError::UnspecifiedField(
                "intercept_icp_e8s".to_string(),
            )
        })?;
        if to_direct_participation_icp_e8s <= from_direct_participation_icp_e8s {
            return Err(LinearScalingCoefficientValidationError::EmptyInterval {
                from_direct_participation_icp_e8s,
                to_direct_participation_icp_e8s,
            });
        }
        if slope_denominator == 0 {
            return Err(LinearScalingCoefficientValidationError::DenominatorIsZero);
        }
        if slope_numerator > slope_denominator {
            return Err(
                LinearScalingCoefficientValidationError::NumeratorGreaterThanDenominator {
                    slope_numerator,
                    slope_denominator,
                },
            );
        }
        Ok(Self {
            from_direct_participation_icp_e8s,
            to_direct_participation_icp_e8s,
            slope_numerator,
            slope_denominator,
            intercept_icp_e8s,
        })
    }
}

enum MaxNeuronsFundParticipationValidationError {
    // This value must be specified.
    Unspecified,
    // Does not make sense if no SNS neurons can be created.
    BelowSingleParticipationLimit {
        max_neurons_fund_participation_icp_e8s: u64,
        min_participant_icp_e8s: u64,
    },
    // The Neuron's Fund should never provide over 50% of the collected funds.
    AboveHalfOfSwapIcpMax {
        max_neurons_fund_participation_icp_e8s: u64,
        half_of_max_icp_e8s: u64,
    },
}

impl ToString for MaxNeuronsFundParticipationValidationError {
    fn to_string(&self) -> String {
        let prefix = "MaxNeuronsFundParticipationValidationError: ";
        match self {
            Self::Unspecified => {
                format!(
                    "{}max_neurons_fund_participation_icp_e8s must be specified.",
                    prefix
                )
            }
            Self::BelowSingleParticipationLimit {
                max_neurons_fund_participation_icp_e8s,
                min_participant_icp_e8s,
            } => {
                format!(
                    "{}max_neurons_fund_participation_icp_e8s ({}) \
                    should be greater than or equal min_participant_icp_e8s ({}).",
                    prefix, max_neurons_fund_participation_icp_e8s, min_participant_icp_e8s,
                )
            }
            Self::AboveHalfOfSwapIcpMax {
                max_neurons_fund_participation_icp_e8s,
                half_of_max_icp_e8s,
            } => {
                format!(
                    "{}max_neurons_fund_participation_icp_e8s ({}) \
                    should be less than or equal half_of_max_icp_e8s ({}).",
                    prefix, max_neurons_fund_participation_icp_e8s, half_of_max_icp_e8s,
                )
            }
        }
    }
}

#[derive(Debug)]
pub enum LinearScalingCoefficientVecValidationError {
    LinearScalingCoefficientsOutOfRange(usize),
    LinearScalingCoefficientsUnordered(
        ValidatedLinearScalingCoefficient,
        ValidatedLinearScalingCoefficient,
    ),
    IrregularLinearScalingCoefficients(ValidatedLinearScalingCoefficient),
    LinearScalingCoefficientValidationError(LinearScalingCoefficientValidationError),
}

impl ToString for LinearScalingCoefficientVecValidationError {
    fn to_string(&self) -> String {
        let prefix = "LinearScalingCoefficientVecValidationError: ";
        match self {
            Self::LinearScalingCoefficientsOutOfRange(num_elements) => {
                format!(
                    "{}coefficient_intervals (len={}) must contain at least 1 and at most {} elements.",
                    prefix,
                    num_elements,
                    MAX_LINEAR_SCALING_COEFFICIENT_VEC_LEN,
                )
            }
            Self::LinearScalingCoefficientsUnordered(left, right) => {
                format!(
                    "{}The intervals {:?} and {:?} are ordered incorrectly.",
                    prefix, left, right
                )
            }
            Self::IrregularLinearScalingCoefficients(interval) => {
                format!(
                    "{}The first interval {:?} does not start from 0.",
                    prefix, interval,
                )
            }
            Self::LinearScalingCoefficientValidationError(error) => {
                format!("{}{}", prefix, error.to_string())
            }
        }
    }
}

impl From<LinearScalingCoefficientVecValidationError> for Result<(), String> {
    fn from(value: LinearScalingCoefficientVecValidationError) -> Self {
        Err(value.to_string())
    }
}

#[derive(Debug)]
pub enum NeuronsFundParticipationConstraintsValidationError {
    RelatedFieldUnspecified(String),
    LinearScalingCoefficientVecValidationError(LinearScalingCoefficientVecValidationError),
}

impl ToString for NeuronsFundParticipationConstraintsValidationError {
    fn to_string(&self) -> String {
        let prefix = "NeuronsFundParticipationConstraintsValidationError: ";
        match self {
            Self::RelatedFieldUnspecified(related_field_name) => {
                format!("{}{} must be specified.", prefix, related_field_name,)
            }
            Self::LinearScalingCoefficientVecValidationError(error) => {
                format!("{}{}", prefix, error.to_string())
            }
        }
    }
}

impl From<NeuronsFundParticipationConstraintsValidationError> for Result<(), String> {
    fn from(value: NeuronsFundParticipationConstraintsValidationError) -> Self {
        Err(value.to_string())
    }
}

pub struct ValidatedNeuronsFundParticipationConstraints {
    pub min_direct_participation_threshold_icp_e8s: u64,
    pub max_neurons_fund_participation_icp_e8s: u64,
    pub coefficient_intervals: Vec<ValidatedLinearScalingCoefficient>,
}

impl From<ValidatedNeuronsFundParticipationConstraints> for NeuronsFundParticipationConstraints {
    fn from(value: ValidatedNeuronsFundParticipationConstraints) -> Self {
        Self {
            min_direct_participation_threshold_icp_e8s: Some(
                value.min_direct_participation_threshold_icp_e8s,
            ),
            max_neurons_fund_participation_icp_e8s: Some(
                value.min_direct_participation_threshold_icp_e8s,
            ),
            coefficient_intervals: value
                .coefficient_intervals
                .into_iter()
                .map(LinearScalingCoefficient::from)
                .collect(),
        }
    }
}

impl TryFrom<NeuronsFundParticipationConstraints> for ValidatedNeuronsFundParticipationConstraints {
    type Error = NeuronsFundParticipationConstraintsValidationError;

    fn try_from(value: NeuronsFundParticipationConstraints) -> Result<Self, Self::Error> {
        // Validate min_direct_participation_threshold_icp_e8s
        let min_direct_participation_threshold_icp_e8s = value
            .min_direct_participation_threshold_icp_e8s
            .ok_or_else(|| {
                Self::Error::RelatedFieldUnspecified(
                    "min_direct_participation_threshold_icp_e8s".to_string(),
                )
            })?;

        // Validate max_neurons_fund_participation_icp_e8s
        let max_neurons_fund_participation_icp_e8s = value
            .max_neurons_fund_participation_icp_e8s
            .ok_or_else(|| {
            Self::Error::RelatedFieldUnspecified(
                "max_neurons_fund_participation_icp_e8s".to_string(),
            )
        })?;

        // Validate coefficient_intervals length.
        if !(1..MAX_LINEAR_SCALING_COEFFICIENT_VEC_LEN + 1)
            .contains(&value.coefficient_intervals.len())
        {
            return Err(Self::Error::LinearScalingCoefficientVecValidationError(
                LinearScalingCoefficientVecValidationError::LinearScalingCoefficientsOutOfRange(
                    value.coefficient_intervals.len(),
                ),
            ));
        }

        // Validate individual coefficient_intervals elements, consuming value.
        let coefficient_intervals: Vec<ValidatedLinearScalingCoefficient> = value
            .coefficient_intervals
            .into_iter()
            .map(|interval| ValidatedLinearScalingCoefficient::try_from(interval))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| {
                Self::Error::LinearScalingCoefficientVecValidationError(
            LinearScalingCoefficientVecValidationError::LinearScalingCoefficientValidationError(err)
        )
            })?;

        // Validate that coefficient_intervals forms a partitioning.
        let intervals = &coefficient_intervals;
        intervals
            .iter()
            .zip(intervals.iter().skip(1))
            .find(|(prev, this)| {
                prev.to_direct_participation_icp_e8s != this.from_direct_participation_icp_e8s
            })
            .map_or(Ok(()), |(prev, this)| {
                Err(Self::Error::LinearScalingCoefficientVecValidationError(
                    LinearScalingCoefficientVecValidationError::LinearScalingCoefficientsUnordered(
                        prev.clone(),
                        this.clone(),
                    ),
                ))
            })?;

        // Validate that coefficient_intervals starts from 0.
        if let Some(first_interval) = intervals.first() {
            if first_interval.from_direct_participation_icp_e8s != 0 {
                return Err(Self::Error::LinearScalingCoefficientVecValidationError(
                    LinearScalingCoefficientVecValidationError::IrregularLinearScalingCoefficients(
                        first_interval.clone(),
                    ),
                ));
            }
        }

        Ok(Self {
            min_direct_participation_threshold_icp_e8s,
            max_neurons_fund_participation_icp_e8s,
            coefficient_intervals,
        })
    }
}

/// An invertible function is a function that has an inverse.
///
/// Say we have an invertible function `f(x: u64) -> u64` and its inverse is `g(y: u64) -> u64`.
/// Then the equality `g(f(x)) = x` must hold for all `x` s.t. `g(f(x))` is defined.
///
/// Additionally, the equality `f(g(y)) = y` must hold for all `y` s.t. `f(g(y))` is defined.
pub trait InvertibleFunction {
    fn apply(&self, x: u64) -> Decimal;
    fn invert(&self, x: Decimal) -> Result<u64, String>;
}

pub struct SimpleLinearFunction {}

impl InvertibleFunction for SimpleLinearFunction {
    fn apply(&self, x: u64) -> Decimal {
        u64_to_dec(x)
    }

    fn invert(&self, x: Decimal) -> Result<u64, String> {
        x.to_u64()
            .ok_or_else(|| format!("{:?} cannot be converted to u64", x))
    }
}

pub trait Interval {
    fn from(&self) -> u64;
    fn to(&self) -> u64;
    fn contains(&self, x: u64) -> bool {
        self.from() <= x && x < self.to()
    }
}

impl Interval for ValidatedLinearScalingCoefficient {
    fn from(&self) -> u64 {
        self.from_direct_participation_icp_e8s
    }

    fn to(&self) -> u64 {
        self.to_direct_participation_icp_e8s
    }
}

pub trait IntervalPartition<I> {
    fn intervals(&self) -> Vec<&I>;

    fn find_interval(&self, x: u64) -> Option<&I>
    where
        I: Interval,
    {
        let intervals = &self.intervals();
        let mut i = 0_usize;
        let mut j = intervals.len() - 1;
        while i <= j {
            let m = (i + j) / 2;
            if intervals[m].to() <= x {
                // If x == intervals[m].to, then x \in intervals[m+1]; move rightwards.
                // ... [intervals[m].from, intervals[m].to) ... x ...
                i = m + 1;
            } else if x < intervals[m].from() {
                // exclusive, since x==intervals[m].from ==> x \in intervals[m]; move leftwards.
                // ... x ... [intervals[m].from, intervals[m].to) ...
                j = m - 1;
            } else {
                // x \in intervals[m]
                return Some(intervals[m]);
            }
        }
        None
    }
}

impl IntervalPartition<ValidatedLinearScalingCoefficient>
    for ValidatedNeuronsFundParticipationConstraints
{
    fn intervals(&self) -> Vec<&ValidatedLinearScalingCoefficient> {
        self.coefficient_intervals.iter().collect()
    }
}

pub struct NeuronsInterval<T> {
    from_direct_participation_icp_e8s: u64,
    to_direct_participation_icp_e8s: Option<u64>,
    neurons: Vec<T>,
}

impl<T> Interval for NeuronsInterval<T> {
    fn from(&self) -> u64 {
        self.from_direct_participation_icp_e8s
    }

    fn to(&self) -> u64 {
        self.to_direct_participation_icp_e8s.unwrap_or(u64::MAX)
    }
}

impl<T> IntervalPartition<NeuronsInterval<T>> for Vec<NeuronsInterval<T>> {
    fn intervals(&self) -> Vec<&NeuronsInterval<T>> {
        self.iter().collect()
    }
}

pub struct MatchedParticipationFunction {
    function: Box<dyn Fn(u64) -> Decimal>,
    params: ValidatedNeuronsFundParticipationConstraints,
}

impl MatchedParticipationFunction {
    pub fn new(
        function: Box<dyn Fn(u64) -> Decimal>,
        params: ValidatedNeuronsFundParticipationConstraints,
    ) -> Result<Self, String> {
        // TODO[NNS1-2619]: validate params
        Ok(Self { function, params })
    }

    pub fn apply(&self, direct_participation_icp_e8s: u64) -> Decimal {
        // Normally, this threshold follows from `self.function`, a.k.a. the "ideal" participation
        // matching function. However, we add an explicit check here in order to make this
        // threashold more prominantly visible from readong the code. In addition, having this
        // branch allows us to use functions with a less complicated shape in the tests.
        if direct_participation_icp_e8s < self.params.min_direct_participation_threshold_icp_e8s {
            return dec!(0.0);
        }

        let intervals = &self.params.coefficient_intervals;
        // This condition is always satisfied, as `self.params` has been validated. We add it here
        // again for verbosity.
        assert!(
            !intervals.is_empty(),
            "There must be at least one interval."
        );

        // Special case A: direct_participation_icp_e8s is less than the first interval.
        if direct_participation_icp_e8s
            < intervals.first().unwrap().from_direct_participation_icp_e8s
        {
            // This should not happen in practice, as the first interval should contain 0.
            return dec!(0.0);
        }

        // Special case B: direct_participation_icp_e8s is greated than or equal to the last
        // interval's upper bound.
        if intervals.last().unwrap().to_direct_participation_icp_e8s <= direct_participation_icp_e8s
        {
            return u64_to_dec(u64::min(
                self.params.max_neurons_fund_participation_icp_e8s,
                MAX_THEORETICAL_NEURONS_FUND_PARTICIPATION_AMOUNT_ICP_E8S,
            ));
        }

        // Otherwise, direct_participation_icp_e8s must fall into one of the intervals.
        if let Some(ValidatedLinearScalingCoefficient {
            slope_numerator,
            slope_denominator,
            intercept_icp_e8s,
            ..
        }) = self.params.find_interval(direct_participation_icp_e8s)
        {
            // This value is how much of Neurons' Fund maturity we should "ideally" allocate.
            let ideal = (self.function)(direct_participation_icp_e8s);

            // Convert to Decimal
            let intercept_icp_e8s = u64_to_dec(*intercept_icp_e8s);
            let slope_numerator = Decimal::from(*slope_numerator);
            let slope_denominator = Decimal::from(*slope_denominator);

            // Normally, `self.params.max_neurons_fund_participation_icp_e8s` should be set to a
            // *reasonable* value. Since this value is computed based on the overall amount of
            // maturity in the Neurons' Fund (at the time when the swap is being opened), in theory
            // it could grow indefinitely. To safeguard against overly massive Neurons' Fund
            // participation to a single SNS swap, the NNS Governance (which manages the
            // Neurons' Fund) should limit the Neurons' Fund maximal theoretically possible amount
            // of participation also by `MAX_THEORETICAL_NEURONS_FUND_PARTICIPATION_AMOUNT_ICP_E8S`.
            // Here, we apply this threshold again for making it more explicit.
            let hard_cap = u64_to_dec(u64::min(
                self.params.max_neurons_fund_participation_icp_e8s,
                MAX_THEORETICAL_NEURONS_FUND_PARTICIPATION_AMOUNT_ICP_E8S,
            ));

            // This value is how much of Neurons' Fund maturity can "effectively" be allocated.
            // This value may be less than or equal to the "ideal" value above, due to:
            // (1) Some Neurons' fund neurons being too small to participate at all (at this direct
            //     participation amount, `direct_participation_icp_e8s`). This is taken into account
            //     via the `(slope_numerator / slope_denominator)` factor.
            // (2) Some Neurons' fund neurons being too big to fully participate (at this direct
            //     participation amount, `direct_participation_icp_e8s`). This is taken into account
            //     via the `intercept_icp_e8s` component.
            // (3) The computed overall participation amount (unexpectedly) exceeded `hard_cap`; so
            //     we enforce the limited at `hard_cap`.
            let effective = hard_cap.min(intercept_icp_e8s.saturating_add(
                // slope_denominator can't be zero as it has been validated.
                // See `LinearScalingCoefficientValidationError::DenominatorIsZero`.
                (slope_numerator / slope_denominator).saturating_mul(ideal),
            ));
            return effective;
        }

        unreachable!(
            "Found a bug in MatchedParticipationFunction.apply({})",
            direct_participation_icp_e8s
        );
    }
}

mod tests {
    use super::{
        dec_to_u64, u64_to_dec, InvertibleFunction, MatchedParticipationFunction,
        SimpleLinearFunction,
    };
    use crate::neurons_fund::ValidatedNeuronsFundParticipationConstraints;
    use ic_nervous_system_common::E8;
    use ic_sns_swap::pb::v1::{LinearScalingCoefficient, NeuronsFundParticipationConstraints};
    use rust_decimal::{
        prelude::{FromPrimitive, ToPrimitive},
        Decimal,
    };
    use rust_decimal_macros::dec;

    #[test]
    fn test_simple_linear_function() {
        let f = SimpleLinearFunction {};
        let run_test_for_a = |x: u64| {
            let y = f.apply(x);
            let x1 = f.invert(y).unwrap();
            assert_eq!(x, x1);
        };
        let run_test_for_b = |y: Decimal| {
            let x = f.invert(y).unwrap();
            let y1 = f.apply(x);
            assert_eq!(y, y1);
        };
        run_test_for_a(0);
        run_test_for_a(77 * E8);
        run_test_for_a(888 * E8 + 123);
        run_test_for_a(9_999 * E8);

        run_test_for_b(u64_to_dec(0));
        run_test_for_b(u64_to_dec(77 * E8));
        run_test_for_b(u64_to_dec(888 * E8 + 123));
        run_test_for_b(u64_to_dec(9_999 * E8));
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
        let params = ValidatedNeuronsFundParticipationConstraints::try_from(params).unwrap();
        let f = SimpleLinearFunction {};
        let g: MatchedParticipationFunction =
            MatchedParticipationFunction::new(Box::from(move |x| f.apply(x)), params).unwrap();
        // Below min_direct_participation_threshold_icp_e8s
        assert_eq!(dec_to_u64(g.apply(0)).unwrap(), 0);
        // Falls into Interval A, thus we expect slope(0.5) * x + intercept_icp_e8s(111)
        assert_eq!(dec_to_u64(g.apply(90 * E8)).unwrap(), 45 * E8 + 111);
        // Falls into Interval B, thus we expect slope(0.6) * x + intercept_icp_e8s(222)
        assert_eq!(dec_to_u64(g.apply(100 * E8)).unwrap(), 60 * E8 + 222);
        // Falls into Interval C, thus we expect slope(0.7) * x + intercept_icp_e8s(333)
        assert_eq!(dec_to_u64(g.apply(5_000 * E8)).unwrap(), 3_500 * E8 + 333);
        // Falls into Interval D, thus we expect slope(0.8) * x + intercept_icp_e8s(444)
        assert_eq!(
            dec_to_u64(g.apply(100_000 * E8 - 1)).unwrap(),
            80_000 * E8 - 1 + 444
        );
        // Falls into Interval D, thus we expect slope(0.9) * x + intercept_icp_e8s(555)
        assert_eq!(
            dec_to_u64(g.apply(100_000 * E8)).unwrap(),
            90_000 * E8 + 555
        );
        // Beyond the last interval
        assert_eq!(
            dec_to_u64(g.apply(1_000_000 * E8)).unwrap(),
            max_neurons_fund_participation_icp_e8s
        );
        // Extremely high value
        assert_eq!(
            dec_to_u64(g.apply(u64::MAX)).unwrap(),
            max_neurons_fund_participation_icp_e8s
        );
    }
}
