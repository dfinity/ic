//! Polynomial operations other than the standard rust ones such as addition and
//! subtraction.

use super::*;

impl Polynomial {
    /// Evaluate the polynomial at x
    /// Note: This uses Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
    pub fn evaluate_at(&self, x: &Fr) -> Fr {
        let mut coefficients = self.coefficients.iter().rev();
        let first = coefficients.next();
        match first {
            None => Fr::zero(),
            Some(ans) => {
                let mut ans: Fr = *ans;
                for coeff in coefficients {
                    ans.mul_assign(&x);
                    ans.add_assign(&coeff);
                }
                ans
            }
        }
    }

    pub fn interpolate(samples: &[(Fr, Fr)]) -> Self {
        if samples.is_empty() {
            return Polynomial::zero();
        }
        // Interpolates on the first `i` samples.
        let mut poly = Polynomial::constant(samples[0].1);
        let mut minus_s0 = samples[0].0;
        minus_s0.negate();
        // Is zero on the first `i` samples.
        let mut base = Polynomial::from(vec![minus_s0, Fr::one()]);

        // We update `base` so that it is always zero on all previous samples, and
        // `poly` so that it has the correct values on the previous samples.
        for (ref x, ref y) in &samples[1..] {
            // Scale `base` so that its value at `x` is the difference between `y` and
            // `poly`'s current value at `x`: Adding it to `poly` will then make
            // it correct for `x`.
            let mut diff = *y;
            diff.sub_assign(&poly.evaluate_at(x));
            if let Some(base_inv) = base.evaluate_at(x).inverse() {
                diff.mul_assign(&base_inv);
                base *= diff;
                poly += &base;

                // Finally, multiply `base` by X - x, so that it is zero at `x`, too, now.
                let mut minus_x = *x;
                minus_x.negate();
                base *= Polynomial::from(vec![minus_x, Fr::one()]);
            }
        }
        poly
    }
}
