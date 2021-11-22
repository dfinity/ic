use crate::*;
use rand_core::{CryptoRng, RngCore};

/// A Polynomial whose coefficients are scalars in an elliptic curve group
///
/// The coefficients are stored in little-endian ordering, ie a_0 is
/// self.coefficients[0]
#[derive(Clone, Debug)]
pub struct Polynomial {
    curve: EccCurveType,
    coefficients: Vec<EccScalar>,
}

impl Eq for Polynomial {}

impl PartialEq for Polynomial {
    fn eq(&self, other: &Self) -> bool {
        if self.curve != other.curve {
            return false;
        }

        // Accept leading zero elements
        let max_coef = std::cmp::max(self.coefficients.len(), other.coefficients.len());

        for i in 0..max_coef {
            if self.coeff(i) != other.coeff(i) {
                return false;
            }
        }

        true
    }
}

impl Polynomial {
    pub fn new(curve: EccCurveType, coefficients: Vec<EccScalar>) -> ThresholdEcdsaResult<Self> {
        if !coefficients.iter().all(|s| s.curve_type() == curve) {
            return Err(ThresholdEcdsaError::CurveMismatch);
        }
        Ok(Self {
            curve,
            coefficients,
        })
    }

    /// Returns the polynomial with constant value `0`.
    pub fn zero(curve: EccCurveType) -> ThresholdEcdsaResult<Self> {
        Self::new(curve, vec![])
    }

    /// Creates a random polynomial with the specified number of coefficients
    pub fn random<R: CryptoRng + RngCore>(
        curve: EccCurveType,
        num_coefficients: usize,
        rng: &mut R,
    ) -> ThresholdEcdsaResult<Self> {
        let mut coefficients = Vec::with_capacity(num_coefficients);

        for _ in 0..num_coefficients {
            coefficients.push(EccScalar::random(curve, rng)?)
        }

        Self::new(curve, coefficients)
    }

    /// Creates a random polynomial with the specified number of coefficients,
    /// one of which is the specified constant
    pub fn random_with_constant<R: CryptoRng + RngCore>(
        constant: EccScalar,
        num_coefficients: usize,
        rng: &mut R,
    ) -> ThresholdEcdsaResult<Self> {
        if num_coefficients == 0 {
            return Err(ThresholdEcdsaError::InvalidArguments(
                "Cannot have degree=0 polynomial with given constant".to_string(),
            ));
        }

        let curve = constant.curve_type();
        let mut coefficients = Vec::with_capacity(num_coefficients);

        coefficients.push(constant);

        for _ in 1..num_coefficients {
            coefficients.push(EccScalar::random(curve, rng)?)
        }

        Self::new(curve, coefficients)
    }

    /// Return the type of scalars this Polynomial is constructed of
    pub fn curve_type(&self) -> EccCurveType {
        self.curve
    }

    fn coeff(&self, idx: usize) -> EccScalar {
        match self.coefficients.get(idx) {
            Some(s) => *s,
            None => EccScalar::zero(self.curve_type()),
        }
    }

    /// Return the coefficients resized to the desired size
    ///
    /// The return value is zero-padded on the high coefficients as
    /// necessary. It is ensured that no coefficients are truncated.
    pub fn get_coefficients(
        &self,
        num_coefficients: usize,
    ) -> ThresholdEcdsaResult<Vec<EccScalar>> {
        if self.coefficients.len() > num_coefficients {
            for c in &self.coefficients[num_coefficients..] {
                if !c.is_zero() {
                    return Err(ThresholdEcdsaError::InvalidArguments(
                        "Too many coefficients".to_string(),
                    ));
                }
            }
        }

        let mut coeff = Vec::with_capacity(num_coefficients);

        for i in 0..num_coefficients {
            coeff.push(self.coeff(i));
        }

        Ok(coeff)
    }

    /// Return the count of non-zero coefficients
    pub fn non_zero_coefficients(&self) -> usize {
        let zeros = self
            .coefficients
            .iter()
            .rev()
            .take_while(|c| c.is_zero())
            .count();

        self.coefficients.len() - zeros
    }

    /// Polynomial addition
    fn add(&self, rhs: &Self) -> ThresholdEcdsaResult<Self> {
        if self.curve_type() != rhs.curve_type() {
            return Err(ThresholdEcdsaError::CurveMismatch);
        }

        let max_coef = std::cmp::max(self.coefficients.len(), rhs.coefficients.len());

        let mut res = Vec::with_capacity(max_coef);
        for idx in 0..max_coef {
            let x = self.coeff(idx);
            let y = rhs.coeff(idx);
            res.push(x.add(&y)?);
        }
        Self::new(self.curve_type(), res)
    }

    /// Compute product of a polynomial and a polynomial
    fn mul(&self, rhs: &Self) -> ThresholdEcdsaResult<Self> {
        if self.curve_type() != rhs.curve_type() {
            return Err(ThresholdEcdsaError::CurveMismatch);
        }

        let n_coeffs = self.coefficients.len() + rhs.coefficients.len() - 1;
        let curve = self.curve_type();

        let zero = EccScalar::zero(curve);
        let mut coeffs = vec![zero; n_coeffs];
        for (i, ca) in self.coefficients.iter().enumerate() {
            for (j, cb) in rhs.coefficients.iter().enumerate() {
                let tmp = ca.mul(cb)?;
                coeffs[i + j] = coeffs[i + j].add(&tmp)?;
            }
        }
        Self::new(curve, coeffs)
    }

    /// Compute product of a polynomial and a scalar
    fn mul_scalar(&self, scalar: &EccScalar) -> ThresholdEcdsaResult<Self> {
        if self.curve_type() != scalar.curve_type() {
            return Err(ThresholdEcdsaError::CurveMismatch);
        }

        let n_coeffs = self.coefficients.len();
        let mut coeffs = Vec::with_capacity(n_coeffs);

        for i in 0..n_coeffs {
            coeffs.push(self.coefficients[i].mul(scalar)?);
        }

        Self::new(self.curve_type(), coeffs)
    }

    /// Evaluate the polynomial at x
    ///
    /// This uses Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
    pub fn evaluate_at(&self, x: &EccScalar) -> ThresholdEcdsaResult<EccScalar> {
        if self.curve_type() != x.curve_type() {
            return Err(ThresholdEcdsaError::CurveMismatch);
        }

        if self.coefficients.is_empty() {
            return Ok(EccScalar::zero(self.curve_type()));
        }

        // Could this instead be done using fold or reduce?
        let mut coefficients = self.coefficients.iter().rev();
        let mut ans = *coefficients
            .next()
            .expect("Iterator was unexpectedly empty");

        for coeff in coefficients {
            ans = ans.mul(x)?;
            ans = ans.add(coeff)?;
        }
        Ok(ans)
    }

    /// Polynomial interpolation
    pub fn interpolate(
        curve: EccCurveType,
        samples: &[(EccScalar, EccScalar)],
    ) -> ThresholdEcdsaResult<Self> {
        if samples.is_empty() {
            return Polynomial::zero(curve);
        }

        let one = EccScalar::one(curve);

        // Constant polynomial interpolating the first sample `(x_0,y_0)`.
        let mut poly = Polynomial::new(curve, vec![samples[0].1])?;
        let mut minus_s0 = samples[0].0;
        minus_s0 = minus_s0.negate()?;
        // Is zero on the first `i` samples.
        // Degree 1 polynomial evaluating to 0 in the first evaluation point `x_0`.
        let mut base = Polynomial::new(curve, vec![minus_s0, one])?;

        // We update `base` so that it is always zero on all previous samples, and
        // `poly` so that it has the correct values on the previous samples.
        for (ref x, ref y) in &samples[1..] {
            if x.curve_type() != curve || y.curve_type() != curve {
                return Err(ThresholdEcdsaError::CurveMismatch);
            }
            // Scale `base` so that its value at `x` is the difference between `y` and
            // `poly`'s current value at `x`: Adding it to `poly` will then make
            // Difference between the current sample `y_i` and the value of `poly` at the
            // current evaluation point `x_i`: `y_i - poly(x_i)`.
            let mut diff = y.sub(&poly.evaluate_at(x)?)?;

            // The inverse of the `base` polynomial evaluated at the current point:
            // `1/base(x_i)`.
            let inv = base.evaluate_at(x)?.invert()?;

            if !inv.is_zero() {
                // Scaling factor for the base polynomial: `(y_i-poly(x_i))/base(x_i)`
                diff = diff.mul(&inv)?;
                // Scale `base` so that the result:
                // * Its value at `x_i` is the difference between `y_i` and `poly`'s current
                //   value at `x_i`,
                // * Its value is 0 at all previous evaluation points `x_j` for `j<i`.
                // `base(x) = base(x)(y_i-poly(x_i))/base(x_i)`
                base = base.mul_scalar(&diff)?;
                // Shift `poly` by `base` so that it has same degree of base and value `y_j` at
                // `x_j` for all j in 0..=i: `poly(x)=poly(x)+base(x)`
                poly = poly.add(&base)?;

                // Update `base` to a degree `i+1` polynomial that evaluates to 0 for all points
                // `x_j` for j in 0..=i: `base(x) = base(x)(x-x_i)`
                base = base.mul(&Polynomial::new(curve, vec![x.negate()?, one])?)?;
            }
        }
        Ok(poly)
    }
}

/// A simple (discrete log) commitment to a polynomial
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimpleCommitment {
    pub points: Vec<EccPoint>,
}

impl SimpleCommitment {
    /// Create a new simple commitment
    ///
    /// The polynomial must have at most num_coefficients coefficients
    pub fn new(poly: &Polynomial, num_coefficients: usize) -> ThresholdEcdsaResult<Self> {
        let curve = EccCurve::new(poly.curve_type());
        let g = curve.generator_g()?;

        let mut points = Vec::with_capacity(num_coefficients);

        for coeff in poly.get_coefficients(num_coefficients)? {
            points.push(g.scalar_mul(&coeff)?);
        }

        Ok(Self { points })
    }
}

/// A Pederson commitment to a polynomial
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PedersenCommitment {
    pub points: Vec<EccPoint>,
}

impl PedersenCommitment {
    /// Create a new Pederson commitment
    ///
    /// Both polynomials must have at most num_coefficients coefficients.
    /// The masking polynomial should be randomly generated with a secure
    /// random number generator.
    pub fn new(
        p_values: &Polynomial,
        p_masking: &Polynomial,
        num_coefficients: usize,
    ) -> ThresholdEcdsaResult<Self> {
        if p_values.curve_type() != p_masking.curve_type() {
            return Err(ThresholdEcdsaError::CurveMismatch);
        }

        let curve = EccCurve::new(p_values.curve_type());
        let g = curve.generator_g()?;
        let h = curve.generator_h()?;

        let coeffs_values = p_values.get_coefficients(num_coefficients)?;
        let coeffs_masking = p_masking.get_coefficients(num_coefficients)?;

        let mut points = Vec::with_capacity(num_coefficients);

        for (coeff_values, coeff_masking) in coeffs_values.iter().zip(coeffs_masking) {
            // compute c = g*a + h*b
            let c = g.mul_points(coeff_values, &h, &coeff_masking)?;
            points.push(c);
        }

        Ok(Self { points })
    }
}
