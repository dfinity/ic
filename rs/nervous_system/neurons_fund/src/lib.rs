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

/// This is a theoretical limit which should be smaller than any realistic amount of maturity
/// that practically needs to be reserved from the Neurons' Fund for a given SNS swap.
pub const MAX_THEORETICAL_NEURONS_FUND_PARTICIPATION_AMOUNT_ICP_E8S: u64 = 333_000 * E8;

// The maximum number of bytes that a serialized representation of an ideal matching function
// `IdealMatchedParticipationFunction` may have.
pub const MAX_MATCHING_FUNCTION_SERIALIZED_REPRESENTATION_SIZE_BYTES: usize = 1_000;

// The maximum number of intervals for scaling ideal Neurons' Fund participation down to effective
// participation. Theoretically, this number should be greater than double the number of neurons
// participating in the Neurons' Fund. Although the currently chosen value is quite high, it is
// still significantly smaller than `usize::MAX`, allowing to reject an misformed
// SnsInitPayload.coefficient_intervals structure with obviously too many elements.
pub const MAX_LINEAR_SCALING_COEFFICIENT_VEC_LEN: usize = 100_000;

/// The implementation of `Decimal::from_u64` cannot fail.
pub fn u64_to_dec(x: u64) -> Decimal {
    Decimal::from_u64(x).unwrap()
}

pub fn dec_to_u64(x: Decimal) -> Result<u64, String> {
    if x.is_sign_negative() {
        return Err(format!("Cannot convert negative value {:?} to u64.", x));
    }
    if x > u64_to_dec(u64::MAX) {
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

pub fn rescale_to_icp(x_icp_e8s: u64) -> Decimal {
    u64_to_dec(x_icp_e8s) * dec!(0.000_000_01)
}

/// Attempts to rescale a decimal amount of ICPs to ICP e8s.
pub fn rescale_to_icp_e8s(x_icp: Decimal) -> Result<u64, String> {
    x_icp
        .checked_mul(u64_to_dec(E8))
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

/// A monotonically non-decreasing function. Returns a decimal amount of ICP (not e8s).
pub trait NonDecreasingFunction {
    fn apply(&self, x_icp_e8s: u64) -> Result<Decimal, String>;

    /// Simply unwraps the result from `self.apply()`.
    fn apply_unchecked(&self, x_icp_e8s: u64) -> Decimal {
        self.apply(x_icp_e8s).unwrap()
    }

    /// Returns `self.apply(x)` with the Ok result rescaled to ICP e8s.
    fn apply_and_rescale_to_icp_e8s(&self, x_icp_e8s: u64) -> Result<u64, String> {
        self.apply(x_icp_e8s).and_then(rescale_to_icp_e8s)
    }

    /// The least argument value (in ICP e8s) at which the function reaches its supremum.
    fn max_argument_icp_e8s(&self) -> Result<u64, String> {
        // A general version of this function could be implemented via binary search.
        Ok(u64::MAX)
    }

    /// Attempts to compute the `(x, f(x))`` pairs for `x in [0..self.max_argument_icp_e8s()]`
    /// with `num_samples` steps. Returned pairs are in ICP. Used in debugging.
    fn plot(&self, num_samples: NonZeroU64) -> Result<Vec<(Decimal, Decimal)>, String> {
        let max_argument_icp_e8s = self.max_argument_icp_e8s()?;
        let num_samples: u64 = num_samples.into();
        let step = max_argument_icp_e8s / num_samples;
        (0..=num_samples)
            .map(|i| {
                let x_icp_e8s = i * step;
                let y_icp = self.apply(x_icp_e8s)?;
                let x_icp = rescale_to_icp(x_icp_e8s);
                Ok((x_icp, y_icp))
            })
            .collect::<Result<Vec<(Decimal, Decimal)>, String>>()
    }
}

/// An invertible function is a function that has an inverse (a.k.a. monotonically non-decreasing).
///
/// Say we have an invertible function `f(x: u64) -> u64` and its inverse is `g(y: u64) -> u64`.
/// Then the equality `g(f(x)) = x` must hold for all `x` s.t. `g(f(x))` is defined.
///
/// Additionally, the equality `f(g(y)) = y` must hold for all `y` s.t. `f(g(y))` is defined.
pub trait InvertibleFunction: NonDecreasingFunction {
    /// This method searches an inverse of `y` given the function defined by `apply`.
    ///
    /// An error is returned if the function defined by `apply` is not monotonically increasing.
    ///
    /// The default implementation assumes the function is non-descending
    fn invert(&self, target_y: Decimal) -> Result<u64, String> {
        if target_y.is_sign_negative() {
            return Err(format!("Cannot invert negative value {}.", target_y));
        }

        let left: u64 = 0;
        let right: u64 = self.max_argument_icp_e8s()?;

        // Search to find the highest `lower` where `f(lower) < target_y`,
        // and the lowest `higher` where `f(higher) >= target_y`.
        // These form the upper and lower bound of the "true" inverse.
        let search_result = binary_search::search_with_fallible_predicate(
            |x| Ok::<_, String>(self.apply(*x)? >= target_y),
            left,
            right,
        )?;
        let error = |x| Ok::<_, String>((self.apply(x)? - target_y).abs());
        match search_result {
            // binary_search::search will return the two values inside the range that inclusively
            // "enclose" the exact inverse, if present. Let's return whichever was closer
            (Some(lower), Some(upper)) => {
                if error(lower)? < error(upper)? {
                    Ok(lower)
                } else {
                    Ok(upper)
                }
            }
            // Otherwise, it'll return the beginning or end of the range.
            // This case will be exercised if u64::MAX is less than the true
            // inverse
            (Some(lower), None) => {
                if error(lower)?.is_zero() {
                    Ok(lower)
                } else {
                    Err(format!(
                        "inverse of function appears to be greater than {lower}"
                    ))
                }
            }
            // This case will be exercised if 0 is equal to or greater than the
            // true inverse
            (None, Some(upper)) => {
                if error(upper)?.is_zero() {
                    Ok(upper)
                } else {
                    Err(format!(
                        "inverse of function appears to be lower than {upper}"
                    ))
                }
            }
            (None, None) => Err("invertible function must be non-decreasing".to_string()),
        }
    }
}

impl<T: NonDecreasingFunction> InvertibleFunction for T {}

#[derive(Clone, Debug)]
pub struct ValidatedLinearScalingCoefficient {
    pub from_direct_participation_icp_e8s: u64,
    pub to_direct_participation_icp_e8s: u64,
    pub slope_numerator: u64,
    pub slope_denominator: u64,
    pub intercept_icp_e8s: u64,
}

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
#[derive(Debug, Clone)]
struct Atom {
    pub param: Decimal,
    pub degree: u8,
}

/// Unoptimized yet simple implementation, avoiding the `decimal::maths` dependency.
/// The main reason why the `decimal::maths` implementation is not ideal is becasue it defines
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
#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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
        T: Into<Decimal> + std::fmt::Debug,
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
                let coefficient = coefficient.into();
                // Casting `i` to `u8` and computing `degree - i` is safe becasue we checked above
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

    pub fn eval(&self) -> Result<Decimal, String> {
        self.members
            .iter()
            .enumerate()
            .fold(Ok(Decimal::ZERO), |total, (i, member)| {
                let member = member.eval().map_err(|e| {
                    format!(
                        "Cannot evaluate binomial member #{} of {:?}: {}",
                        i, self, e
                    )
                })?;
                let total = total?;
                total
                    .checked_add(member)
                    .ok_or_else(|| format!("Decimal overflow while computing {:?}.", self))
            })
    }
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
struct PolynomialMatchingFunctionCache {
    f_1: F1Cache,
    f_2: F2Cache,
    f_3: F3Cache,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PolynomialMatchingFunctionPersistentData {
    pub t_1: Decimal,
    pub t_2: Decimal,
    pub t_3: Decimal,
    pub t_4: Decimal,
    pub cap: Decimal,
}

impl PolynomialMatchingFunctionCache {
    fn from_persistent_data(
        data: &PolynomialMatchingFunctionPersistentData,
    ) -> Result<Self, String> {
        let f_1 = F1Cache::new(data.t_1, data.t_2, data.cap)
            .map_err(|e| format!("Error while computing cached data for f_1: {}", e))?;
        let f_2 = F2Cache::new(data.t_2, data.t_3, data.cap)
            .map_err(|e| format!("Error while computing cached data for f_2: {}", e))?;
        let f_3 = F3Cache::new(data.t_3, data.t_4, data.cap)
            .map_err(|e| format!("Error while computing cached data for f_3: {}", e))?;
        Ok(Self { f_1, f_2, f_3 })
    }
}

#[derive(Debug, Clone)]
pub struct PolynomialMatchingFunction {
    persistent_data: PolynomialMatchingFunctionPersistentData,
    cache: PolynomialMatchingFunctionCache,
}

impl SerializableFunction for PolynomialMatchingFunction {
    fn serialize(&self) -> String {
        // Serialization should never fail, as structure is bounded, and there should be tests
        // that demonstrate that this succeeds.
        serde_json::to_string(&self.persistent_data).unwrap()
    }
}

impl PolynomialMatchingFunction {
    fn from_persistant_data(
        persistent_data: PolynomialMatchingFunctionPersistentData,
    ) -> Result<Self, String> {
        let cache = PolynomialMatchingFunctionCache::from_persistent_data(&persistent_data)?;
        Ok(Self {
            persistent_data,
            cache,
        })
    }

    /// Creates a monotonically non-decreasing polynomial function for Neurons' Fund Matched Funding.
    pub fn new(total_maturity_equivalent_icp_e8s: u64) -> Self {
        // Computations defined in ICP rather than ICP e8s to avoid multiplication overflows for
        // the `Decimal` type for the range of values that this type is expected to operate on.
        let global_cap_icp =
            rescale_to_icp(MAX_THEORETICAL_NEURONS_FUND_PARTICIPATION_AMOUNT_ICP_E8S);
        let total_maturity_equivalent_icp = rescale_to_icp(total_maturity_equivalent_icp_e8s);
        let cap = global_cap_icp.min(
            dec!(0.1) * total_maturity_equivalent_icp, // 10%
        );
        let persistent_data = PolynomialMatchingFunctionPersistentData {
            t_1: dec!(0.1) * global_cap_icp, // 10%
            t_2: dec!(0.3) * global_cap_icp, // 30%
            t_3: dec!(0.5) * global_cap_icp, // 50%
            t_4: dec!(2.0) * cap,            // 200%
            cap,
        };
        // TODO: support this case
        assert!(
            persistent_data.t_4 > persistent_data.t_3,
            "t_4 ({}) should be greater than t_3 ({}).",
            persistent_data.t_4,
            persistent_data.t_3
        );
        // Unwrapping here is safe due to the FIXME test.
        Self::from_persistant_data(persistent_data).unwrap()
    }
}

impl DeserializableFunction for PolynomialMatchingFunction {
    /// Attempts to create an instance of `Self` from a serialized representation, `repr`.
    fn from_repr(repr: &str) -> Result<Box<Self>, String> {
        let persistent_data = serde_json::from_str(repr).map_err(|e| e.to_string())?;
        Self::from_persistant_data(persistent_data).map(Box::from)
    }
}

impl NonDecreasingFunction for PolynomialMatchingFunction {
    fn apply(&self, x_icp_e8s: u64) -> Result<Decimal, String> {
        // Local variables in this function without the _icp_e8s postfix are in ICP.
        let x = rescale_to_icp(x_icp_e8s);
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

    fn max_argument_icp_e8s(&self) -> Result<u64, String> {
        rescale_to_icp_e8s(self.persistent_data.t_4)
    }
}

pub type PolynomialNeuronsFundParticipation =
    ValidatedNeuronsFundParticipationConstraints<PolynomialMatchingFunction>;

// -------------------------------------------------------------------------------------------------
// ------------------- IntervalPartition -----------------------------------------------------------
// -------------------------------------------------------------------------------------------------

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
        if intervals.is_empty() {
            return None;
        }
        let mut i = 0_usize;
        // Cannot underflow as intervals.len() >= 1.
        let mut j = intervals.len() - 1;
        while i <= j {
            // [Spec] assume loop guard: i <= j
            // [Spec] assume invariant: 0 <= i <= j+1, 0 <= j < intervals.len()

            // Without `as u64`, an overflow would occur if e.g. `i==j==usize::MAX-1`. Note that
            // the actual value of `usize::MAX` on Wasm32 targets is just `4294967295`, less than
            // `u64::MAX`. Converting back to usize is safe, as the average is not greater
            // than `j: usize`.
            let m = (((i as u64) + (j as u64)) / 2) as usize;
            // [Spec] assert(*) i <= m <= j  -- from math.
            if intervals[m].to() <= x {
                // If x == intervals[m].to, then x \in intervals[m+1]; move rightwards.
                // ... [intervals[m].from, intervals[m].to) ... x ...
                i = m + 1;
                // [Spec] assert invariant: 0 <= i   <= j+1, 0 <= j < intervals.len()
                // [Spec] -- `i==m+1`; `j` did not change.
                // [Spec] assert: 0 <= m+1 <= j+1
                // [Spec] -- given `0 <= m` from (*), we know that `0 <= m+1`.
                // [Spec] -- `m+1 <= j+1`  <==>  `m <= j`.
                // [Spec] -- `m <= j` follows from (*). QED
            } else if x < intervals[m].from() {
                // exclusive, since x==intervals[m].from ==> x \in intervals[m]; move leftwards.
                // ... x ... [intervals[m].from, intervals[m].to) ...
                if m == 0 {
                    // The leftmost interval starts from a value greated than `x`.
                    return None;
                }
                // [Spec] assert(**) 0 < m
                j = m - 1;
                // [Spec] assert invariant: 0 <= i <= j+1, 0 <= j < intervals.len()
                // [Spec] -- `i` did not change; `j==m-1`.
                // [Spec] assert: 0 <= i <= m-1+1, 0 <= m-1 < intervals.len()
                // [Spec] assert: 0 <= i <= m,     0 <= m-1 < intervals.len()
                // [Spec] -- `i <= m` follows from (*).
                // [Spec] -- given `0 < m` from (**), we know that `0 <= m-1`. QED
            } else {
                // x \in intervals[m]
                return Some(intervals[m]);
            }
        }
        None
    }
}

impl<F> IntervalPartition<ValidatedLinearScalingCoefficient>
    for ValidatedNeuronsFundParticipationConstraints<F>
{
    fn intervals(&self) -> Vec<&ValidatedLinearScalingCoefficient> {
        self.coefficient_intervals.iter().collect()
    }
}

pub trait MatchedParticipationFunction {
    fn apply(&self, direct_participation_icp_e8s: u64) -> Result<u64, String>;

    /// Simply unwraps the result from `self.apply()`.
    fn apply_unchecked(&self, direct_participation_icp_e8s: u64) -> u64 {
        self.apply(direct_participation_icp_e8s).unwrap()
    }
}

impl<F> MatchedParticipationFunction for ValidatedNeuronsFundParticipationConstraints<F>
where
    F: NonDecreasingFunction,
{
    /// Returns a decimal amount of ICP e8s, i.e., a number with a whole and a fractional part.
    fn apply(&self, direct_participation_icp_e8s: u64) -> Result<u64, String> {
        // Normally, this threshold follows from `self.ideal_matched_participation_function.function`,
        // a.k.a. the "ideal" participation matching function. However, we add an explicit check
        // here in order to make this threashold more prominantly visible from readong the code.
        // In addition, having this branch allows us to use functions with a less complicated shape
        // in the tests.
        if direct_participation_icp_e8s < self.min_direct_participation_threshold_icp_e8s {
            return Ok(0);
        }

        let intervals = &self.coefficient_intervals;
        // This condition is always satisfied, as `self` has been validated. We add it here
        // again for verbosity.
        if intervals.is_empty() {
            return Err("There must be at least one interval.".to_string());
        }

        // Special case A: direct_participation_icp_e8s is less than the first interval.
        if direct_participation_icp_e8s
            < intervals.first().unwrap().from_direct_participation_icp_e8s
        {
            // This should not happen in practice, as the first interval should contain 0.
            return Ok(0);
        }

        // Special case B: direct_participation_icp_e8s is greated than or equal to the last
        // interval's upper bound.
        if intervals.last().unwrap().to_direct_participation_icp_e8s <= direct_participation_icp_e8s
        {
            return Ok(u64::min(
                self.max_neurons_fund_participation_icp_e8s,
                MAX_THEORETICAL_NEURONS_FUND_PARTICIPATION_AMOUNT_ICP_E8S,
            ));
        }

        // Otherwise, direct_participation_icp_e8s must fall into one of the intervals.
        if let Some(ValidatedLinearScalingCoefficient {
            slope_numerator,
            slope_denominator,
            intercept_icp_e8s,
            ..
        }) = self.find_interval(direct_participation_icp_e8s)
        {
            // This value is how much of Neurons' Fund maturity we should "ideally" allocate.
            let ideal_icp = self
                .ideal_matched_participation_function
                .apply(direct_participation_icp_e8s)?;

            // Convert to Decimal
            let intercept_icp_e8s = rescale_to_icp(*intercept_icp_e8s);
            let slope_numerator = u64_to_dec(*slope_numerator);
            let slope_denominator = u64_to_dec(*slope_denominator);

            // Normally, `self.max_neurons_fund_participation_icp_e8s` should be set to a
            // *reasonable* value. Since this value is computed based on the overall amount of
            // maturity in the Neurons' Fund (at the time when the swap is being opened), in theory
            // it could grow indefinitely. To safeguard against overly massive Neurons' Fund
            // participation to a single SNS swap, the NNS Governance (which manages the
            // Neurons' Fund) should limit the Neurons' Fund maximal theoretically possible amount
            // of participation also by `MAX_THEORETICAL_NEURONS_FUND_PARTICIPATION_AMOUNT_ICP_E8S`.
            // Here, we apply this threshold again for making it more explicit.
            let hard_cap = u64_to_dec(u64::min(
                self.max_neurons_fund_participation_icp_e8s,
                MAX_THEORETICAL_NEURONS_FUND_PARTICIPATION_AMOUNT_ICP_E8S,
            ));

            // This value is how much of Neurons' Fund maturity can "effectively" be allocated.
            // This value may be less than or equal to the `ideal_icp` value above, due to:
            // (1) Some Neurons' fund neurons being too small to participate at all (at this direct
            //     participation amount, `direct_participation_icp_e8s`). This is taken into account
            //     via the `(slope_numerator / slope_denominator)` factor.
            // (2) Some Neurons' fund neurons being too big to fully participate (at this direct
            //     participation amount, `direct_participation_icp_e8s`). This is taken into account
            //     via the `intercept_icp_e8s` component.
            // (3) The computed overall participation amount (unexpectedly) exceeded `hard_cap`; so
            //     we enforce the limited at `hard_cap`.
            let effective_icp = hard_cap.min(intercept_icp_e8s.saturating_add(
                // `slope_denominator`` cannot be zero as it has been validated.
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
