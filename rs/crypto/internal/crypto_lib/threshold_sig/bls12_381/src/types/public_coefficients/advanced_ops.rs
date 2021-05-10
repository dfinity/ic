//! Non-trivial mathematical operations on `PublicCoefficients`.

use super::super::ThresholdError;
use super::*;
use ff::Field;
use group::{CurveAffine, CurveProjective};
use pairing::bls12_381::{Fr, G2};
use std::borrow::Borrow;

impl PublicCoefficients {
    /// Evaluate the public coefficients at x
    pub fn evaluate_at(&self, x: &Fr) -> G2 {
        let mut coefficients = self.coefficients.iter().rev();
        let first = coefficients.next().map(|pk| pk.0);
        match first {
            None => G2::zero(),
            Some(ans) => {
                let mut ans: G2 = ans;
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
    pub fn interpolate<C, B>(samples: &[(Fr, B)]) -> Result<C, ThresholdError>
    where
        C: CurveProjective<Scalar = Fr>,
        B: Borrow<C>,
    {
        let all_x: Vec<Fr> = samples.iter().map(|(x, _)| *x).collect();
        let coefficients = Self::lagrange_coefficients_at_zero(&all_x)?;
        let mut result = C::zero();
        for (coefficient, sample) in coefficients.iter().zip(samples.iter().map(|(_, y)| y)) {
            result.add_assign(&sample.borrow().into_affine().mul(*coefficient))
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
    pub fn lagrange_coefficients_at_zero(samples: &[Fr]) -> Result<Vec<Fr>, ThresholdError> {
        let len = samples.len();
        if len == 0 {
            return Ok(Vec::new());
        }
        if len == 1 {
            return Ok(vec![Fr::one()]);
        }

        // The j'th numerator is the product of all `x_prod[i]` for `i!=j`.
        // Note: The usual subtractions can be omitted as we are computing the Lagrange
        // coefficient at zero.
        let mut x_prod: Vec<Fr> = Vec::with_capacity(len);
        let mut tmp = Fr::one();
        x_prod.push(tmp);
        for x in samples.iter().take(len - 1) {
            tmp.mul_assign(x);
            x_prod.push(tmp);
        }
        tmp = Fr::one();
        for (i, x) in samples[1..].iter().enumerate().rev() {
            tmp.mul_assign(x);
            x_prod[i].mul_assign(&tmp);
        }

        for (lagrange_0, x_i) in x_prod.iter_mut().zip(samples) {
            // Compute the value at 0 of the Lagrange polynomial that is `0` at the other
            // data points but `1` at `x`.
            let mut denom = Fr::one();
            for x_j in samples.iter().filter(|x_j| *x_j != x_i) {
                let mut diff = *x_j;
                diff.sub_assign(x_i);
                denom.mul_assign(&diff);
            }
            lagrange_0.mul_assign(&denom.inverse().ok_or(ThresholdError::DuplicateX)?);
        }
        Ok(x_prod)
    }

    pub(super) fn remove_zeros(&mut self) {
        let zeros = self
            .coefficients
            .iter()
            .rev()
            .take_while(|c| c.0.is_zero())
            .count();
        let len = self.coefficients.len() - zeros;
        self.coefficients.truncate(len)
    }
}
