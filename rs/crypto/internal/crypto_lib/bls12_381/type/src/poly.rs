use crate::Scalar;
use rand::{CryptoRng, RngCore};

/// A Polynomial whose coefficients are scalars in an elliptic curve group
///
/// The coefficients are stored in little-endian ordering, ie a_0 is
/// self.coefficients\[0\]
#[derive(Clone, Debug, Eq)]
pub struct Polynomial {
    coefficients: Vec<Scalar>,
}

impl PartialEq for Polynomial {
    fn eq(&self, other: &Self) -> bool {
        // Accept leading zero elements
        let max_coef = std::cmp::max(self.degree(), other.degree());

        for i in 0..max_coef {
            if self.coeff(i) != other.coeff(i) {
                return false;
            }
        }

        true
    }
}

impl Polynomial {
    /// Create a new polynomial with the specified coefficients
    pub fn new(coefficients: Vec<Scalar>) -> Self {
        Self { coefficients }
    }

    /// Returns the polynomial with constant value `0`.
    pub fn zero() -> Self {
        Self::new(vec![])
    }

    /// Creates a random polynomial with the specified number of coefficients
    pub fn random<R: CryptoRng + RngCore>(num_coefficients: usize, rng: &mut R) -> Self {
        let mut coefficients = Vec::with_capacity(num_coefficients);

        for _ in 0..num_coefficients {
            coefficients.push(Scalar::random(rng))
        }

        Self { coefficients }
    }

    /// Returns the coefficient at the specified index
    ///
    /// Returns zero if the index is larger than the polynomial
    pub fn coeff(&self, idx: usize) -> &Scalar {
        match self.coefficients.get(idx) {
            Some(s) => s,
            None => Scalar::zero_ref(),
        }
    }

    /// Return the coefficients of the polynomial
    pub fn coefficients(&self) -> &[Scalar] {
        &self.coefficients
    }

    /// Return the degree of the polynomial
    pub fn degree(&self) -> usize {
        self.coefficients.len()
    }

    /// Set a single coefficient of the polynomial to a new value
    pub fn set_coeff(&mut self, idx: usize, value: Scalar) {
        if idx >= self.coefficients.len() {
            self.coefficients.resize(idx, Scalar::zero());
        }
        self.coefficients[idx] = value;
    }

    /// Evaluate this polynomial at the given point
    pub fn evaluate_at(&self, x: &Scalar) -> Scalar {
        if self.coefficients.is_empty() {
            return Scalar::zero();
        }

        let mut coefficients = self.coefficients.iter().rev();
        let mut ans = coefficients
            .next()
            .expect("Iterator was unexpectedly empty")
            .clone();

        for coeff in coefficients {
            ans *= x;
            ans += coeff;
        }
        ans
    }
}

impl std::ops::Add<&Polynomial> for &Polynomial {
    type Output = Polynomial;

    fn add(self, other: &Polynomial) -> Polynomial {
        let max_degree = std::cmp::max(self.degree(), other.degree());
        let mut coeffs = Vec::with_capacity(max_degree);

        for i in 0..max_degree {
            coeffs.push(self.coeff(i) + other.coeff(i));
        }
        Polynomial::new(coeffs)
    }
}

impl std::ops::Add<Polynomial> for Polynomial {
    type Output = Polynomial;

    fn add(self, other: Polynomial) -> Polynomial {
        &self + &other
    }
}
