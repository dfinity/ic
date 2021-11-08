//! Constructors and conversion from/to other types
use super::*;
use crate::types::bls::random_bls12_381_scalar;

impl Polynomial {
    ///////////////
    // Constructors

    /// Returns the polynomial with constant value `0`.
    pub fn zero() -> Self {
        Polynomial {
            coefficients: vec![],
        }
    }

    /// Returns `true` if the polynomial is the constant value `0`.
    pub fn is_zero(&self) -> bool {
        self.coefficients
            .iter()
            .all(|coefficient| coefficient.is_zero())
    }

    pub fn constant(c: Scalar) -> Self {
        Polynomial::from(vec![c])
    }

    /// Creates a random polynomial.
    pub fn random<R: RngCore>(number_of_coefficients: usize, rng: &mut R) -> Self {
        let coefficients: Vec<Scalar> = iter::repeat(())
            .map(|()| random_bls12_381_scalar(rng))
            .take(number_of_coefficients)
            .collect();
        Polynomial::from(coefficients)
    }

    /// Remove trailing zeros; this should be applied by internal constructors
    /// to get the canonical representation of each polynomial.
    pub(super) fn remove_zeros(&mut self) {
        let zeros = self
            .coefficients
            .iter()
            .rev()
            .take_while(|c| c.is_zero())
            .count();
        let len = self.coefficients.len() - zeros;
        self.coefficients.truncate(len)
    }
}

/// Creates a new `Polynomial` instance from a vector of prime field elements
/// representing the coefficients of the polynomial.
impl From<Vec<Scalar>> for Polynomial {
    fn from(coefficients: Vec<Scalar>) -> Self {
        let mut ans = Polynomial { coefficients };
        ans.remove_zeros();
        ans
    }
}
