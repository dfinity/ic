//! Non-trivial mathematical operations on `PublicCoefficients`.

use super::super::ThresholdError;
use super::*;
use bls12_381::{G1Projective, G2Projective, Scalar};
use std::borrow::Borrow;
use std::ops::{AddAssign, Mul, MulAssign, SubAssign};

impl PublicCoefficients {
    /// Evaluate the public coefficients at x
    pub fn evaluate_at(&self, x: &Scalar) -> G2Projective {
        let mut coefficients = self.coefficients.iter().rev();
        let first = coefficients.next().map(|pk| pk.0);
        match first {
            None => G2Projective::identity(),
            Some(ans) => {
                let mut ans: G2Projective = ans;
                for coeff in coefficients {
                    ans.mul_assign(*x);
                    ans.add_assign(&coeff.0);
                }
                ans
            }
        }
    }

    /// Given a list of samples `(x, f(x) * g)` for a polynomial `f`, returns
    /// `f(0) * g`.
    /// See: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach
    pub fn interpolate_g1(
        samples: &[(Scalar, G1Projective)],
    ) -> Result<G1Projective, ThresholdError> {
        let all_x: Vec<Scalar> = samples.iter().map(|(x, _)| *x).collect();
        let coefficients = Self::lagrange_coefficients_at_zero(&all_x)?;
        let mut result = G1Projective::identity();
        for (coefficient, sample) in coefficients.iter().zip(samples.iter().map(|(_, y)| y)) {
            result.add_assign(&sample.borrow().mul(*coefficient))
        }
        Ok(result)
    }

    /// Given a list of samples `(x, f(x) * g)` for a polynomial `f`, returns
    /// `f(0) * g`.
    /// See: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach
    pub fn interpolate_g2(
        samples: &[(Scalar, G2Projective)],
    ) -> Result<G2Projective, ThresholdError> {
        let all_x: Vec<Scalar> = samples.iter().map(|(x, _)| *x).collect();
        let coefficients = Self::lagrange_coefficients_at_zero(&all_x)?;
        let mut result = G2Projective::identity();
        for (coefficient, sample) in coefficients.iter().zip(samples.iter().map(|(_, y)| y)) {
            result.add_assign(&sample.borrow().mul(*coefficient))
        }
        Ok(result)
    }

    /// Compute the Lagrange coefficients at x=0.
    ///
    /// # Arguments
    /// * `samples` is a list of values x_0, x_1, ...x_n.
    /// # Result
    /// * `[lagrange_0, lagrange_1, ..., lagrange_n]` where:
    ///    * lagrange_i = numerator_i/denominator_i
    ///    * numerator_i = x_0 * x_1 * ... * x_(i-1) * x_(i+1) * ... * x_n
    ///    * denominator_i = (x_0 - x_i) * (x_1 - x_i) * ... * (x_(i-1) - x_i) *
    ///      (x_(i+1) - x_i) * ... * (x_n - x_i)
    /// # Errors
    /// This will return an error if the denominator is zero.
    pub fn lagrange_coefficients_at_zero(
        samples: &[Scalar],
    ) -> Result<Vec<Scalar>, ThresholdError> {
        let len = samples.len();
        if len == 0 {
            return Ok(Vec::new());
        }
        if len == 1 {
            return Ok(vec![Scalar::one()]);
        }

        // The j'th numerator is the product of all `x_prod[i]` for `i!=j`.
        // Note: The usual subtractions can be omitted as we are computing the Lagrange
        // coefficient at zero.
        let mut x_prod: Vec<Scalar> = Vec::with_capacity(len);
        let mut tmp = Scalar::one();
        x_prod.push(tmp);
        for x in samples.iter().take(len - 1) {
            tmp.mul_assign(x);
            x_prod.push(tmp);
        }
        tmp = Scalar::one();
        for (i, x) in samples[1..].iter().enumerate().rev() {
            tmp.mul_assign(x);
            x_prod[i].mul_assign(&tmp);
        }

        for (lagrange_0, x_i) in x_prod.iter_mut().zip(samples) {
            // Compute the value at 0 of the Lagrange polynomial that is `0` at the other
            // data points but `1` at `x`.
            let mut denom = Scalar::one();
            for x_j in samples.iter().filter(|x_j| *x_j != x_i) {
                let mut diff = *x_j;
                diff.sub_assign(x_i);
                denom.mul_assign(&diff);
            }
            let inv = denom.invert();

            if bool::from(inv.is_none()) {
                return Err(ThresholdError::DuplicateX);
            }

            let inv = inv.unwrap();
            lagrange_0.mul_assign(inv);
        }
        Ok(x_prod)
    }

    pub(super) fn remove_zeros(&mut self) {
        let zeros = self
            .coefficients
            .iter()
            .rev()
            .take_while(|c| bool::from(c.0.is_identity()))
            .count();
        let len = self.coefficients.len() - zeros;
        self.coefficients.truncate(len)
    }
}
