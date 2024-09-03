//! Implementation of common types for Matched Funding.
//!
//! More concretely, these types are suiteable for deriving the amount of maturity that
//! the Neuron's Fund should use to participate in an SNS token swap. That amount is a function of
//! the swap's direct participation (i.e., the amount of ICP that direct participants send/commit
//! to the swap). Because it is an increasing function of direct participation, this amount
//! is called "Matched Funding". The function is customized via some of the SNS's configuration.

use std::num::NonZeroU64;

use ic_nervous_system_common::{binary_search, E8};
use rust_decimal::{
    prelude::{FromPrimitive, ToPrimitive},
    Decimal, RoundingStrategy,
};
use rust_decimal_macros::dec;
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod binomial_tests;
#[cfg(test)]
mod polynomial_matching_function_tests;
pub mod test_functions;

pub(crate) const LOG_PREFIX: &str = "[Neurons' Fund] ";

// The maximum number of bytes that a serialized representation of an ideal matching function
// `IdealMatchedParticipationFunction` may have.
pub const MAX_MATCHING_FUNCTION_SERIALIZED_REPRESENTATION_SIZE_BYTES: usize = 1_000;

// The maximum number of intervals for scaling ideal Neurons' Fund participation down to effective
// participation. Theoretically, this number should be greater than double the number of neurons
// participating in the Neurons' Fund. Although the currently chosen value is quite high, it is
// still significantly smaller than `usize::MAX`, allowing to reject an misformed
// SnsInitPayload.coefficient_intervals structure with obviously too many elements.
pub const MAX_LINEAR_SCALING_COEFFICIENT_VEC_LEN: usize = 100_000;

/// The implementation of `Decimal::from_u64` cannot fail, but we propagate the result to the caller
/// to protect against library implementation changes.
pub fn u64_to_dec(x: u64) -> Result<Decimal, String> {
    Decimal::from_u64(x).ok_or_else(|| format!("Cannot convert {:?} to Decimal.", x))
}

pub fn dec_to_u64(x: Decimal) -> Result<u64, String> {
    if x.is_sign_negative() {
        return Err(format!("Cannot convert negative value {:?} to u64.", x));
    }
    if x > u64_to_dec(u64::MAX)? {
        return Err(format!(
            "cannot convert value {x} to u64 as it is above u64::MAX ({}).",
            u64::MAX,
        ));
    }
    // The same could be achieved via `x.round()`, but we opt for verbosity.
    let x = x.round_dp_with_strategy(0, RoundingStrategy::MidpointNearestEven);
    // We already checked that 0 <= x; the only reason `to_u64` can fail at this point is overflow.
    Decimal::to_u64(&x)
        .ok_or_else(|| format!("Overflow while trying to convert value {:?} to u64.", x))
}

pub fn rescale_to_icp(x_icp_e8s: u64) -> Result<Decimal, String> {
    u64_to_dec(x_icp_e8s).map(|x_icp_e8s| x_icp_e8s * dec!(0.000_000_01))
}

/// Attempts to rescale a decimal amount of ICPs to ICP e8s. Warning: this operation is lossy.
pub fn rescale_to_icp_e8s(x_icp: Decimal) -> Result<u64, String> {
    x_icp
        .checked_mul(u64_to_dec(E8)?)
        .ok_or_else(|| {
            format!(
                "Overflow while rescaling {} ICP to e8s within Decimal.",
                x_icp
            )
        })
        .and_then(dec_to_u64)
}

/// Implementations of this trait can be created from a string-based representation. This is used
/// in conjunction with `IdealMatchingFunction` for typing functions that need to be deserialized.
pub trait DeserializableFunction {
    fn from_repr(repr: &str) -> Result<Box<Self>, String>;
}

pub trait SerializableFunction {
    fn serialize(&self) -> String;
}

pub trait IdealMatchingFunction:
    InvertibleFunction + SerializableFunction + std::fmt::Debug
{
}

impl<F: InvertibleFunction + SerializableFunction + std::fmt::Debug> IdealMatchingFunction for F {}

/// A function for matching ICP amounts.
pub trait MatchingFunction {
    /// Applies `self` over the specified amount in ICP e8s, returning an amount in ICP (not e8s).
    fn apply(&self, x_icp_e8s: u64) -> Result<Decimal, String>;

    /// Returns `self.apply(x)` with the Ok result rescaled to ICP e8s.
    fn apply_and_rescale_to_icp_e8s(&self, x_icp_e8s: u64) -> Result<u64, String> {
        self.apply(x_icp_e8s).and_then(rescale_to_icp_e8s)
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum InvertError {
    ValueIsNegative(Decimal),
    MaxArgumentValueError(String),
    FunctionApplicationError(String),
    MonotonicityAssumptionViolation {
        left: u64,
        target_y: Decimal,
        right: u64,
    },
    InvertValueAboveU64Range {
        lower: u64,
        target_y: Decimal,
    },
    InvertValueBelowU64Range {
        target_y: Decimal,
        upper: u64,
    },
}

impl std::fmt::Display for InvertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let invert_error_cause = match self {
            Self::ValueIsNegative(value) => {
                format!("negative value {}.", value)
            }
            Self::MaxArgumentValueError(error) => {
                format!("due to maximum argument error: {}", error)
            }
            Self::FunctionApplicationError(error) => {
                format!("due to function application error: {}", error)
            }
            Self::MonotonicityAssumptionViolation {
                left,
                target_y,
                right,
            } => {
                format!(
                    "at target_y={}, as function is decreasing between {} and {}.",
                    target_y, left, right,
                )
            }
            Self::InvertValueAboveU64Range { lower, target_y } => {
                format!(
                    "at target_y={}, as function's inverse appears to be above {}.",
                    target_y, lower,
                )
            }
            Self::InvertValueBelowU64Range { target_y, upper } => {
                format!(
                    "at target_y={}, as function's inverse appears to be below {}.",
                    target_y, upper,
                )
            }
        };

        write!(f, "Cannot invert {}", invert_error_cause)
    }
}

/// An invertible function is a function that has an inverse (a.k.a. monotonically non-decreasing).
///
/// Say we have an invertible function `f(x: u64) -> u64` and its inverse is `g(y: u64) -> u64`.
/// Then the equality `g(f(x)) = x` must hold for all `x` s.t. `g(f(x))` is defined.
///
/// Additionally, the equality `f(g(y)) = y` must hold for all `y` s.t. `f(g(y))` is defined.
pub trait InvertibleFunction: MatchingFunction {
    /// This method searches an inverse of `y` given the function defined by `self.apply`.
    ///
    /// An error is returned if the function defined by `self.apply` is not monotonically increasing.
    ///
    /// The default implementation assumes the function is non-decreasing.
    fn invert(&self, target_y: Decimal) -> Result<u64, InvertError> {
        if target_y.is_sign_negative() {
            return Err(InvertError::ValueIsNegative(target_y));
        }

        let left = 0_u64;
        let right = u64::MAX;

        // Search to find the highest `lower` where `f(lower) < target_y`,
        // and the lowest `higher` where `f(higher) >= target_y`.
        // These form the upper and lower bound of the "true" inverse.
        let search_result = binary_search::search_with_fallible_predicate(
            |x: &u64| -> Result<bool, InvertError> {
                let y = self
                    .apply(*x)
                    .map_err(InvertError::FunctionApplicationError)?;
                Ok(y >= target_y)
            },
            left,
            right,
        )?;
        let error = |x: u64| -> Result<Decimal, InvertError> {
            let y = self
                .apply(x)
                .map_err(InvertError::FunctionApplicationError)?;
            Ok((y - target_y).abs())
        };
        match search_result {
            // binary_search::search will return the two values inside the range that inclusively
            // "enclose" the exact inverse, if present. Let's return whichever was closer
            (Some(lower), Some(upper)) => {
                let (error_l, error_r) = (error(lower)?, error(upper)?);
                // <= means that we pick the leftmost value if the errors are zero for both bounds.
                if error_l <= error_r {
                    Ok(lower)
                } else {
                    Ok(upper)
                }
            }
            // Otherwise, it'll return the beginning or end of the range.
            // This case will be exercised if `u64::MAX` is less than the true inverse.
            (Some(lower), None) => {
                if error(lower)?.is_zero() {
                    Ok(lower)
                } else {
                    Err(InvertError::InvertValueAboveU64Range { lower, target_y })
                }
            }
            // This case will be exercised if 0 is equal to or greater than the
            // true inverse
            (None, Some(upper)) => {
                if error(upper)?.is_zero() {
                    Ok(upper)
                } else {
                    Err(InvertError::InvertValueBelowU64Range { target_y, upper })
                }
            }
            (None, None) => Err(InvertError::MonotonicityAssumptionViolation {
                left,
                target_y,
                right,
            }),
        }
    }

    /// Attempts to find the least argument value (in ICP e8s) at which the function reaches its
    /// supremum.
    fn max_argument_icp_e8s(&self) -> Result<u64, String> {
        let max_y_icp = self.apply(u64::MAX)?;
        self.invert(max_y_icp).map_err(|err| err.to_string())
    }

    /// Attempts to compute the `(x, f(x))` pairs for `x in [0..self.max_argument_icp_e8s()]`
    /// with `num_samples` steps. Returned pairs are in ICP. Used in debugging.
    fn plot(&self, num_samples: NonZeroU64) -> Result<Vec<(Decimal, Decimal)>, String> {
        let max_argument_icp_e8s = self.max_argument_icp_e8s()?;
        let num_samples = u64::from(num_samples);
        // Integer division is justified in this case as max_argument_icp_e8s >> num_samples.
        let step = max_argument_icp_e8s / num_samples;
        (0..=num_samples)
            .map(|i| {
                let x_icp_e8s = i * step;
                let y_icp = self.apply(x_icp_e8s)?;
                let x_icp = rescale_to_icp(x_icp_e8s)?;
                Ok((x_icp, y_icp))
            })
            .collect::<Result<Vec<(Decimal, Decimal)>, String>>()
    }

    fn dbg_plot(&self) -> String {
        format!(
            "{}: {}",
            std::any::type_name::<Self>(),
            self.plot(NonZeroU64::try_from(30).unwrap())
                .map(|plot| format!("{:?}", plot))
                .unwrap_or_else(|e| e),
        )
    }
}

impl<T: MatchingFunction> InvertibleFunction for T {}

#[derive(Clone, PartialEq, Debug)]
pub struct ValidatedLinearScalingCoefficient {
    pub from_direct_participation_icp_e8s: u64,
    pub to_direct_participation_icp_e8s: u64,
    pub slope_numerator: u64,
    pub slope_denominator: u64,
    pub intercept_icp_e8s: u64,
}

impl Default for ValidatedLinearScalingCoefficient {
    fn default() -> Self {
        Self {
            from_direct_participation_icp_e8s: 0,
            to_direct_participation_icp_e8s: u64::MAX,
            slope_numerator: 1,
            slope_denominator: 1,
            intercept_icp_e8s: 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ValidatedNeuronsFundParticipationConstraints<F> {
    pub min_direct_participation_threshold_icp_e8s: u64,
    pub max_neurons_fund_participation_icp_e8s: u64,
    pub coefficient_intervals: Vec<ValidatedLinearScalingCoefficient>,
    pub ideal_matched_participation_function: Box<F>,
}

// -------------------------------------------------------------------------------------------------
// ------------------- PolynomialMatchingFunction --------------------------------------------------
// -------------------------------------------------------------------------------------------------

/// Polynomial atom. Represents `(param ^ degree)`.
#[derive(Clone, Debug)]
struct Atom {
    pub param: Decimal,
    pub degree: u8,
}

/// Unoptimized yet simple implementation, avoiding the `decimal::maths` dependency.
/// The main reason why the `decimal::maths` implementation is not ideal is because it defines
/// `0^0`, while this may cause confusion and is thus better treated as an error case.
/// More concretely, this function will return an error in the following cases:
/// * If `x` and `exp` are both zero.
/// * If a multiplicative `Decimal` overflow happens during evaluation.
///
/// Suitable for small values of `exp`, hence its type is `u8`.
fn checked_pow(x: Decimal, exp: u8) -> Result<Decimal, String> {
    if x.is_zero() && exp == 0 {
        return Err("0^0 is undefined.".to_string());
    }
    if x.is_zero() {
        return Ok(Decimal::ZERO);
    }
    let mut res = Decimal::ONE;
    for _ in 0..exp {
        res = res
            .checked_mul(x)
            .ok_or_else(|| format!("Decimal overflow while computing {}^{}.", x, exp))?;
    }
    Ok(res)
}

impl Atom {
    pub fn eval(&self) -> Result<Decimal, String> {
        checked_pow(self.param, self.degree)
    }

    pub fn new(param: Decimal, degree: u8) -> Self {
        Self { param, degree }
    }
}

/// Binomial formula member. Represents:
/// ```
/// coefficient * (left.param ^ left.degree) * (right.param ^ right.degree)
/// ```
#[derive(Clone, Debug)]
struct BinomialFormulaMember {
    pub coefficient: Decimal,
    pub left: Atom,
    pub right: Atom,
}

impl BinomialFormulaMember {
    /// Overflow-safe encoding for a binomial member.
    pub fn eval(&self) -> Result<Decimal, String> {
        let left = self.left.eval()?;
        let right = self.right.eval()?;
        self.coefficient
            .checked_mul(left)
            .ok_or_else(|| format!("Decimal overflow while computing {:?}.", self))?
            .checked_mul(right)
            .ok_or_else(|| format!("Decimal overflow while computing {:?}.", self))
    }

    pub fn new(degree: u8, coefficient: Decimal, left: Atom, right: Atom) -> Result<Self, String> {
        let expected_degree = left
            .degree
            .checked_add(right.degree)
            .ok_or_else(|| format!("Overflow while adding {} and {}", left.degree, right.degree))?;
        // Check that the expected degree (i.e., the sum of the degrees of the two atoms in this
        // binomial member) equals the specified degree. This checks that multiple members of
        // the same binomial formula are compatible. For example, `a*(x^2)*(y^3) + b*x*(y^4)` is
        // a consistent binomial of degree 2+3 = 1+4 = 5, while `a*(x^2)*(y^2) + b*x*(y^4)` is not
        // consistent, as the degree of its first member (2+2 = 4) differs from the degree of its
        // second member (1+4 = 5).
        if expected_degree != degree {
            return Err(
                format!(
                    "Expected binomial member degree {}, but left/right atoms have degrees {} and {}, resp.",
                    degree, left.degree, right.degree
                )
            );
        }
        Ok(Self {
            coefficient,
            left,
            right,
        })
    }
}

#[derive(Clone, Debug)]
struct BinomialFormula {
    #[allow(unused)]
    name: String,
    #[allow(unused)]
    degree: u8,
    members: Vec<BinomialFormulaMember>,
}

impl BinomialFormula {
    pub fn new<T>(
        name: &str,
        degree: u8,
        coefficients: Vec<T>,
        left_param: Decimal,
        right_param: Decimal,
    ) -> Result<Self, String>
    where
        T: std::fmt::Debug,
        Decimal: From<T>,
    {
        let name = name.to_string();
        // Width of the Nth row of Pascal's triangle.
        let expected_num_coefficients = degree
            .checked_add(1)
            .ok_or_else(|| "degree overflow in BinomialFormula::new.".to_string())?;
        if coefficients.len() != (expected_num_coefficients as usize) {
            return Err(format!(
                "Cannot create binomial `{}` of degree {} with coefficients: {:?}.",
                name, degree, coefficients,
            ));
        }
        let members = coefficients
            .into_iter()
            .enumerate()
            .map(|(i, coefficient)| {
                let coefficient = Decimal::from(coefficient);
                // Casting `i` to `u8` and computing `degree - i` is safe because we checked above
                // that `coefficients.len() == degree + 1`, so `i <= degree: u8`.
                let i = i as u8;
                let left = Atom::new(left_param, degree - i);
                let right = Atom::new(right_param, i);
                BinomialFormulaMember::new(degree, coefficient, left, right)
            })
            .collect::<Result<Vec<BinomialFormulaMember>, String>>()?;
        Ok(Self {
            name,
            degree,
            members,
        })
    }

    #[allow(clippy::manual_try_fold)]
    pub fn eval(&self) -> Result<Decimal, String> {
        self.members
            .iter()
            .enumerate()
            // Avoid using `try_fold` here as we should not short-circuit errors.
            .fold(Ok(Decimal::ZERO), |overall_result, (i, member)| {
                let sub_result = member.eval().map_err(|e| {
                    format!(
                        "Cannot evaluate binomial member #{} of {:?}: {}",
                        i, self, e
                    )
                });
                match (overall_result, sub_result) {
                    (Ok(total), Ok(sub_total)) => total.checked_add(sub_total).ok_or_else(|| {
                        vec![format!("Decimal overflow while computing {:?}.", self)]
                    }),
                    (Ok(_), Err(err)) => Err(vec![err]),
                    (Err(errs), Ok(_)) => Err(errs),
                    (Err(mut errs), Err(err)) => {
                        errs.push(err);
                        Err(errs)
                    }
                }
            })
            .map_err(|errs| {
                format!(
                    "Cannot evaluate BinomialFormula:\n  - {}",
                    errs.join("\n  - ")
                )
            })
    }
}

#[derive(Clone, PartialEq, Debug)]
struct F1Cache {
    #[allow(unused)]
    t1: Decimal,
    #[allow(unused)]
    t2: Decimal,
    a: Decimal,
    b: Decimal,
    c: Decimal,
    d: Decimal,
    cap: Decimal,
}

impl F1Cache {
    pub fn new(t1: Decimal, t2: Decimal, cap: Decimal) -> Result<Self, String> {
        let a_num = BinomialFormula::new("a_num", 1, vec![2, -1], t1, t2)?.eval()?;
        let a_denom = BinomialFormula::new("a_denom", 3, vec![1, -3, 3, -1], t1, t2)?.eval()?;
        let a = a_num
            .checked_div(a_denom)
            .ok_or("division by zero while computing a in f_1.".to_string())?;

        let b_num = BinomialFormula::new("b_num", 2, vec![-8, 1, 1], t1, t2)?.eval()?;
        let b_denom = BinomialFormula::new("b_denom", 3, vec![2, -6, 6, -2], t1, t2)?.eval()?;
        let b = b_num
            .checked_div(b_denom)
            .ok_or("division by zero while computing b in f_1.".to_string())?;

        let c_num = BinomialFormula::new("c_num", 3, vec![2, 2, -1, 0], t1, t2)?.eval()?;
        let c_denom = BinomialFormula::new("c_denom", 3, vec![1, -3, 3, -1], t1, t2)?.eval()?;
        let c = c_num
            .checked_div(c_denom)
            .ok_or("division by zero while computing c in f_1.".to_string())?;

        let d_num = BinomialFormula::new("d_num", 4, vec![0, -3, 1, 0, 0], t1, t2)?.eval()?;
        let d_denom = BinomialFormula::new("d_denom", 3, vec![2, -6, 6, -2], t1, t2)?.eval()?;
        let d = d_num
            .checked_div(d_denom)
            .ok_or("division by zero while computing d in f_1.".to_string())?;

        Ok(Self {
            t1,
            t2,
            a,
            b,
            c,
            d,
            cap,
        })
    }

    pub fn apply(&self, x: Decimal) -> Result<Decimal, String> {
        let p = BinomialFormula::new("p", 3, vec![self.a, self.b, self.c, self.d], x, dec!(1))?
            .eval()?;
        Ok(self.cap.min(dec!(0.5) * x).min(Decimal::ZERO.max(p)))
    }
}

#[derive(Clone, PartialEq, Debug)]
struct F2Cache {
    #[allow(unused)]
    t2: Decimal,
    #[allow(unused)]
    t3: Decimal,
    a: Decimal,
    b: Decimal,
    c: Decimal,
    d: Decimal,
    cap: Decimal,
}

impl F2Cache {
    pub fn new(t2: Decimal, t3: Decimal, cap: Decimal) -> Result<Self, String> {
        let a_num = BinomialFormula::new("a_num", 1, vec![2, -1], t2, t3)?.eval()?;
        let a_denom = BinomialFormula::new("a_denom", 3, vec![1, -3, 3, -1], t2, t3)?.eval()?;
        let a = a_num
            .checked_div(a_denom)
            .ok_or("division by zero while computing a in f_2.".to_string())?;

        let b_num = BinomialFormula::new("b_num", 2, vec![-5, -5, 4], t2, t3)?.eval()?;
        let b_denom = BinomialFormula::new("b_denom", 3, vec![2, -6, 6, -2], t2, t3)?.eval()?;
        let b = b_num
            .checked_div(b_denom)
            .ok_or("division by zero while computing b in f_2.".to_string())?;

        let c_num = BinomialFormula::new("c_num", 3, vec![1, 2, 2, -2], t2, t3)?.eval()?;
        let c_denom = BinomialFormula::new("c_denom", 3, vec![1, -3, 3, -1], t2, t3)?.eval()?;
        let c = c_num
            .checked_div(c_denom)
            .ok_or("division by zero while computing c in f_2.".to_string())?;

        let d_num = BinomialFormula::new("d_num", 4, vec![0, 0, -5, 3, 0], t2, t3)?.eval()?;
        let d_denom = BinomialFormula::new("d_denom", 3, vec![2, -6, 6, -2], t2, t3)?.eval()?;
        let d = d_num
            .checked_div(d_denom)
            .ok_or("division by zero while computing d in f_2.".to_string())?;

        Ok(Self {
            t2,
            t3,
            a,
            b,
            c,
            d,
            cap,
        })
    }

    pub fn apply(&self, x: Decimal) -> Result<Decimal, String> {
        let p = BinomialFormula::new("p", 3, vec![self.a, self.b, self.c, self.d], x, dec!(1))?
            .eval()?;
        Ok(self.cap.min(x).min(p))
    }
}

#[derive(Clone, PartialEq, Debug)]
struct F3Cache {
    #[allow(unused)]
    t3: Decimal,
    #[allow(unused)]
    t4: Decimal,
    a: Decimal,
    b: Decimal,
    c: Decimal,
    d: Decimal,
    e: Decimal,
    cap: Decimal,
}

impl F3Cache {
    pub fn new(t3: Decimal, t4: Decimal, cap: Decimal) -> Result<Self, String> {
        let a_num = BinomialFormula::new("a_num", 1, vec![-4, 1], t3, t4)?.eval()?;
        let a_denom = BinomialFormula::new("a_denom", 4, vec![2, -8, 12, -8, 2], t3, t4)?.eval()?;
        let a = a_num
            .checked_div(a_denom)
            .ok_or("division by zero while computing a in f_3.".to_string())?;

        let b_num = BinomialFormula::new("b_num", 2, vec![3, 4, -1], t3, t4)?.eval()?;
        let b_denom = BinomialFormula::new("b_denom", 4, vec![1, -4, 6, -4, 1], t3, t4)?.eval()?;
        let b = b_num
            .checked_div(b_denom)
            .ok_or("division by zero while computing b in f_3.".to_string())?;

        let c_num = BinomialFormula::new("c_num", 3, vec![0, -9, 0, 0], t3, t4)?.eval()?;
        let c_denom = BinomialFormula::new("c_denom", 4, vec![1, -4, 6, -4, 1], t3, t4)?.eval()?;
        let c = c_num
            .checked_div(c_denom)
            .ok_or("division by zero while computing c in f_3.".to_string())?;

        let d_num = BinomialFormula::new("d_num", 4, vec![0, 0, 9, -4, 1], t3, t4)?.eval()?;
        let d_denom = BinomialFormula::new("d_denom", 4, vec![1, -4, 6, -4, 1], t3, t4)?.eval()?;
        let d = d_num
            .checked_div(d_denom)
            .ok_or("division by zero while computing d in f_3.".to_string())?;

        let e = {
            let e_denom =
                BinomialFormula::new("e_denom", 4, vec![2, -8, 12, -8, 2], t3, t4)?.eval()?;

            // TODO: Implement `BinomialFormula::div(&self, denom: Decimal) -> Result<Self, String>` for
            // TODO: automating this overflow-mitigating tactic, perhaps with the following syntax:
            // `BinomialFormula::new("e_num", 5, vec![0, 1, -4, 0, 0, 0], t3, t4)?.div(e_denom)?.eval()?`

            // Tactic: e  =  e_num / e_denom  =  (e_num_1 + e_num_2_1 * e_num_2_2) / e_denom
            // =  (e_num_1 / e_denom) + (e_num_2_1 / e_denom) * e_num_2_2  =  e1 + e2.
            let e_num_1 =
                BinomialFormulaMember::new(5, dec!(1), Atom::new(t3, 4), Atom::new(t4, 1))?
                    .eval()?;
            let e_num_2_1 =
                BinomialFormulaMember::new(3, dec!(1), Atom::new(t3, 3), Atom::new(t4, 0))?
                    .eval()?;
            let e_num_2_2 =
                BinomialFormulaMember::new(2, dec!(-4), Atom::new(t3, 0), Atom::new(t4, 2))?
                    .eval()?;

            let e1 = e_num_1
                .checked_div(e_denom)
                .ok_or("division by zero while computing e_num_1 / e_denom in f_3.".to_string())?;
            let e2_1 = e_num_2_1
                .checked_div(e_denom)
                .ok_or("division by zero while computing e2_1 / e_denom in f_3.".to_string())?;
            let e2: Decimal = e2_1
                .checked_mul(e_num_2_2)
                .ok_or("overflow while computing e2_1 * e_num_2_2 in f_3.")?;
            e1.checked_add(e2)
                .ok_or("overflow while computing e1 + e2 in f_3.")?
        };

        Ok(Self {
            t3,
            t4,
            a,
            b,
            c,
            d,
            e,
            cap,
        })
    }

    pub fn apply(&self, x: Decimal) -> Result<Decimal, String> {
        let p = BinomialFormula::new(
            "p",
            4,
            vec![self.a, self.b, self.c, self.d, self.e],
            x,
            dec!(1),
        )?
        .eval()?;
        Ok(self.cap.min(x).min(p))
    }
}

#[derive(Clone, PartialEq, Debug)]
struct PolynomialMatchingFunctionCache {
    f_1: F1Cache,
    f_2: F2Cache,
    f_3: F3Cache,
}

#[derive(Clone, PartialEq, Debug, Deserialize, Serialize)]
struct PolynomialMatchingFunctionPersistentData {
    pub t_1: Decimal,
    pub t_2: Decimal,
    pub t_3: Decimal,
    pub t_4: Decimal,
    pub cap: Decimal,
}

impl PolynomialMatchingFunctionPersistentData {
    pub fn log_unreachable_milestones(&self, human_readable_cap_formula: String) {
        if self.t_4 < self.t_1 {
            println!(
                "{}WARNING: This PolynomialMatchingFunction returns zero for all direct \
                participation amounts, as (2 * {}) ({}) is less than t_1 ({})",
                LOG_PREFIX, human_readable_cap_formula, self.t_4, self.t_1,
            );
        } else if self.t_4 < self.t_2 {
            println!(
                "{}INFO: This PolynomialMatchingFunction returns less than 1/3 of the overall \
                participation amount (for all amounts of direct participation), because \
                (2 * {}) ({}) is less than t_2 ({})",
                LOG_PREFIX, human_readable_cap_formula, self.t_4, self.t_3,
            );
        } else if self.t_4 < self.t_3 {
            println!(
                "{}INFO: This PolynomialMatchingFunction returns less than 1/2 of the overall \
                participation amount (for all amounts of direct participation), because \
                (2 * {}) ({}) is less than t_3 ({})",
                LOG_PREFIX, human_readable_cap_formula, self.t_4, self.t_3,
            );
        }
    }
}

impl PolynomialMatchingFunctionCache {
    fn from_persistent_data(
        data: &PolynomialMatchingFunctionPersistentData,
    ) -> Result<Self, String> {
        let f_1 = F1Cache::new(data.t_1, data.t_2, data.cap)
            .map_err(|e| format!("Error while computing cached data for f_1: {}", e))?;
        let f_2 = F2Cache::new(data.t_2, data.t_3, data.cap)
            .map_err(|e| format!("Error while computing cached data for f_2: {}", e))?;
        let f_3 = if data.t_4 > Decimal::ZERO {
            F3Cache::new(data.t_3, data.t_4, data.cap)
                .map_err(|e| format!("Error while computing cached data for f_3: {}", e))?
        } else {
            // Setting all polynomial coefficients to `1.0` to avoid dealing with `0^0`; at the same
            // time, `cap == 0.0` makes `F3Cache::apply` always return `0.0`, respecting
            // the semantics of `f_3` for `t4 == 0`.
            F3Cache {
                t3: data.t_3,
                t4: data.t_4,
                a: Decimal::ONE,
                b: Decimal::ONE,
                c: Decimal::ONE,
                d: Decimal::ONE,
                e: Decimal::ONE,
                cap: Decimal::ZERO,
            }
        };
        Ok(Self { f_1, f_2, f_3 })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct PolynomialMatchingFunction {
    persistent_data: PolynomialMatchingFunctionPersistentData,
    cache: PolynomialMatchingFunctionCache,
}

/// Notes on the robustness of this implementation.
///
/// In principle, a machine-readable serialization of the bounded type `PolynomialMatchingFunction`
/// should never fail, and there should be tests that demonstrate that this succeeds. However, in
/// the highly unexpected event that the serialization somehow still fails, this implementation
/// should fall back to a human-readable serialization of this function. This would likely push
/// the failure onto the deserialization phase, which is expected to happen only upon an upgrade of
/// the canister that hosts the Neurons' Fund. In that case, the upgrade would fail (due to a stable
/// memory deserialization error, which would likely expect JSON while just a human-readable string
/// would be present), and an engineer would need to intervene. The reason we pay this cost is to
/// avoid complicating the API, e.g., one would need to implement
/// ```
/// impl<F> TryFrom<NeuronsFundParticipation<F>> for NeuronsFundParticipationPb
/// ```
/// instead of
/// ```
/// impl<F> From<NeuronsFundParticipation<F>> for NeuronsFundParticipationPb
/// ```
/// Instead of complicting the API, a better way forward would be to use a fail-safe JSON
/// serialization algorithm for bounded structures.
impl SerializableFunction for PolynomialMatchingFunction {
    fn serialize(&self) -> String {
        match serde_json::to_string(&self.persistent_data) {
            Ok(serialization) => serialization,
            Err(err) => {
                // Fallback in the unlikely event that `serde_json::to_string` fails.
                let fallback_serialization = format!("{:?}", self);
                println!(
                    "{}ERROR: cannot serialize a PolynomialMatchingFunction instance {} into JSON: \
                    {}. Falling back to debug serialization.",
                    LOG_PREFIX, fallback_serialization, err,
                );
                fallback_serialization
            }
        }
    }
}

/// Absolute constraints applicable to all swaps needed in Matched Funding computations. These
/// values are defined in NetowrkEconomics (in XDR) and converted to ICP using the rate from CMC.
///
/// This is an internal representation for `NeuronsFundMatchedFundingCurveCoefficientsPb`.
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct NeuronsFundParticipationLimits {
    pub max_theoretical_neurons_fund_participation_amount_icp: Decimal,
    pub contribution_threshold_icp: Decimal,
    pub one_third_participation_milestone_icp: Decimal,
    pub full_participation_milestone_icp: Decimal,
}

impl PolynomialMatchingFunction {
    /// Attempts to create an instance of `Self` from `persistent_data`. This might fail, e.g.,
    /// if there is an overflow or division by zero during the computation of the polynomial
    /// coefficients.
    fn from_persistent_data(
        persistent_data: PolynomialMatchingFunctionPersistentData,
    ) -> Result<Self, String> {
        let cache = PolynomialMatchingFunctionCache::from_persistent_data(&persistent_data)?;
        Ok(Self {
            persistent_data,
            cache,
        })
    }

    /// Creates a monotonically non-decreasing polynomial function for Neurons' Fund Matched Funding.
    pub fn new(
        total_maturity_equivalent_icp_e8s: u64,
        neurons_fund_participation_limits: NeuronsFundParticipationLimits,
    ) -> Result<Self, String> {
        // Computations defined in ICP rather than ICP e8s to avoid multiplication overflows for
        // the `Decimal` type for the range of values that this type is expected to operate on.
        let global_cap_icp =
            neurons_fund_participation_limits.max_theoretical_neurons_fund_participation_amount_icp;

        let total_maturity_equivalent_icp = rescale_to_icp(total_maturity_equivalent_icp_e8s)?;

        let one_tenth_maturity_equivalent_icp = dec!(0.1) * total_maturity_equivalent_icp;

        let (cap, human_readable_cap_formula) =
            if global_cap_icp <= one_tenth_maturity_equivalent_icp {
                (
                    global_cap_icp,
                    format!(
                        "max_theoretical_neurons_fund_participation_amount_icp ({})",
                        global_cap_icp,
                    ),
                )
            } else {
                (
                    one_tenth_maturity_equivalent_icp,
                    format!(
                        "(0.1 * total_maturity_equivalent_icp ({})) ({})",
                        total_maturity_equivalent_icp, one_tenth_maturity_equivalent_icp,
                    ),
                )
            };

        let persistent_data = PolynomialMatchingFunctionPersistentData {
            t_1: neurons_fund_participation_limits.contribution_threshold_icp,
            t_2: neurons_fund_participation_limits.one_third_participation_milestone_icp,
            t_3: neurons_fund_participation_limits.full_participation_milestone_icp,
            t_4: dec!(2.0) * cap, // 200%
            cap,
        };

        persistent_data.log_unreachable_milestones(human_readable_cap_formula);

        Self::from_persistent_data(persistent_data)
    }
}

impl DeserializableFunction for PolynomialMatchingFunction {
    /// Attempts to create an instance of `Self` from a serialized representation, `repr`.
    fn from_repr(repr: &str) -> Result<Box<Self>, String> {
        let persistent_data = serde_json::from_str(repr).map_err(|e| e.to_string())?;
        Self::from_persistent_data(persistent_data).map(Box::from)
    }
}

impl MatchingFunction for PolynomialMatchingFunction {
    fn apply(&self, x_icp_e8s: u64) -> Result<Decimal, String> {
        // Local variables in this function without the _icp_e8s postfix are in ICP.
        let x = rescale_to_icp(x_icp_e8s)?;
        let (t1, t2, t3, t4) = (
            self.persistent_data.t_1,
            self.persistent_data.t_2,
            self.persistent_data.t_3,
            self.persistent_data.t_4,
        );
        let res = if x < t1 {
            Decimal::ZERO
        } else if t1 <= x && x < t2 {
            self.cache.f_1.apply(x)?
        } else if t2 <= x && x < t3 {
            self.cache.f_2.apply(x)?
        } else if t3 <= x && x < t4 {
            self.cache.f_3.apply(x)?
        } else {
            self.persistent_data.cap
        };
        Ok(res)
    }
}

pub type PolynomialNeuronsFundParticipation =
    ValidatedNeuronsFundParticipationConstraints<PolynomialMatchingFunction>;

// -------------------------------------------------------------------------------------------------
// ------------------- HalfOpenInterval ------------------------------------------------------------
// -------------------------------------------------------------------------------------------------

pub trait HalfOpenInterval {
    fn from(&self) -> u64;
    fn to(&self) -> u64;
    fn contains(&self, x: u64) -> bool {
        self.from() <= x && x < self.to()
    }
    fn find(intervals: &[Self], x: u64) -> Option<&Self>
    where
        Self: Sized,
    {
        if intervals.is_empty() {
            return None;
        }
        let i = 0_usize;
        // Cannot underflow as intervals.len() >= 1.
        let j = intervals.len() - 1;
        let search_result = binary_search::search(|m| x < intervals[*m].from(), i, j);
        match search_result {
            (Some(m), Some(_)) => {
                let interval = &intervals[m];
                // `m` will be the greatest index such that `!(x < intervals[*m].from())`.
                // Can only fail if there is a "gap" with no intervals containing `x`.
                debug_assert!(interval.contains(x));
                Some(interval)
            }
            (Some(m), None) | (None, Some(m)) => {
                let interval = &intervals[m];
                if interval.contains(x) {
                    Some(interval)
                } else {
                    None // There's no interval that contains `x`
                }
            }
            (None, None) => {
                println!(
                    "{}ERROR: cannot perform find_interval as the intervals aren't sorted",
                    LOG_PREFIX,
                );
                None
            }
        }
    }
}

impl HalfOpenInterval for ValidatedLinearScalingCoefficient {
    fn from(&self) -> u64 {
        self.from_direct_participation_icp_e8s
    }

    fn to(&self) -> u64 {
        self.to_direct_participation_icp_e8s
    }
}

pub trait MatchedParticipationFunction {
    fn apply(&self, direct_participation_icp_e8s: u64) -> Result<u64, String>;
}

impl<F> MatchedParticipationFunction for ValidatedNeuronsFundParticipationConstraints<F>
where
    F: MatchingFunction,
{
    /// Returns a decimal amount of ICP e8s, i.e., a number with a whole and a fractional part.
    fn apply(&self, direct_participation_icp_e8s: u64) -> Result<u64, String> {
        let intervals = &self.coefficient_intervals;
        // This condition is always satisfied, as `self` has been validated. We add it here
        // again for verbosity.
        if intervals.is_empty() {
            return Err("There must be at least one interval.".to_string());
        }

        let first_interval = intervals
            .first()
            .ok_or_else(|| "cannot find the first interval".to_string())?;
        let last_interval = intervals
            .last()
            .ok_or_else(|| "cannot find the first interval".to_string())?;

        // Special case A: direct_participation_icp_e8s is less than the first interval.
        if direct_participation_icp_e8s < first_interval.from_direct_participation_icp_e8s {
            // This should not happen in practice, as the first interval should contain 0.
            return Ok(0);
        }

        // Special case B: direct_participation_icp_e8s is greated than or equal to the last
        // interval's upper bound.
        if last_interval.to_direct_participation_icp_e8s <= direct_participation_icp_e8s {
            return Ok(self.max_neurons_fund_participation_icp_e8s);
        }

        // Otherwise, direct_participation_icp_e8s must fall into one of the intervals.
        if let Some(ValidatedLinearScalingCoefficient {
            slope_numerator,
            slope_denominator,
            intercept_icp_e8s,
            ..
        }) = HalfOpenInterval::find(&self.coefficient_intervals, direct_participation_icp_e8s)
        {
            // This value is how much of Neurons' Fund maturity we should "ideally" allocate.
            let ideal_icp = self
                .ideal_matched_participation_function
                .apply(direct_participation_icp_e8s)?;

            // Convert to Decimal
            let intercept_icp = rescale_to_icp(*intercept_icp_e8s)?;
            let slope_numerator = u64_to_dec(*slope_numerator)?;
            let slope_denominator = u64_to_dec(*slope_denominator)?;
            let hard_cap_icp = rescale_to_icp(self.max_neurons_fund_participation_icp_e8s)?;

            // This value is how much of Neurons' Fund maturity can "effectively" be allocated.
            // This value may be less than or equal to the `ideal_icp` value above, due to:
            // (1) Some Neurons' Fund neurons being too small to participate at all (at this direct
            //     participation amount, `direct_participation_icp_e8s`). This is taken into account
            //     via the `(slope_numerator / slope_denominator)` factor.
            // (2) Some Neurons' fund neurons being too big to fully participate (at this direct
            //     participation amount, `direct_participation_icp_e8s`). This is taken into account
            //     via the `intercept_icp` component.
            // (3) The computed overall participation amount (unexpectedly) exceeded `hard_cap_icp`;
            //     so we enforce the limited at `hard_cap_icp`.
            let effective_icp = hard_cap_icp.min(intercept_icp.saturating_add(
                // `slope_denominator` cannot be zero as it has been validated.
                // See `LinearScalingCoefficientValidationError::DenominatorIsZero`.
                // `slope_numerator / slope_denominator` is between 0.0 and 1.0.
                // See `LinearScalingCoefficientValidationError::NumeratorGreaterThanDenominator`.
                (slope_numerator / slope_denominator) * ideal_icp,
            ));
            return rescale_to_icp_e8s(effective_icp);
        }

        Err(format!(
            "Found a bug in MatchedParticipationFunction.apply({})",
            direct_participation_icp_e8s
        ))
    }
}
