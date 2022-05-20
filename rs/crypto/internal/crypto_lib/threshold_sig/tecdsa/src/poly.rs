use crate::*;
use core::fmt::{self, Debug};
use ic_types::crypto::canister_threshold_sig::idkg::IDkgOpening;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use zeroize::Zeroize;

/// A Polynomial whose coefficients are scalars in an elliptic curve group
///
/// The coefficients are stored in little-endian ordering, ie a_0 is
/// self.coefficients\[0\]
#[derive(Clone)]
pub struct Polynomial {
    curve: EccCurveType,
    coefficients: Vec<EccScalar>,
}

impl Debug for Polynomial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.curve {
            EccCurveType::K256 => write!(f, "Polynomial {{curve: K256, coefficients: REDACTED}}"),
            EccCurveType::P256 => write!(f, "Polynomial {{curve: P256, coefficients: REDACTED}}"),
        }
    }
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

    pub fn is_zero(&self) -> bool {
        self.non_zero_coefficients() == 0
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
    pub fn mul(&self, rhs: &Self) -> ThresholdEcdsaResult<Self> {
        let curve_type = self.curve_type();

        if rhs.curve_type() != curve_type {
            return Err(ThresholdEcdsaError::CurveMismatch);
        }

        let lhs_coeffs = self.coefficients.len();
        let rhs_coeffs = rhs.coefficients.len();
        // Slightly over-estimates the size when one of the poly is empty
        let n_coeffs = std::cmp::max(lhs_coeffs + rhs_coeffs, 1) - 1;

        let zero = EccScalar::zero(curve_type);
        let mut coeffs = vec![zero; n_coeffs];

        for (i, ca) in self.coefficients.iter().enumerate() {
            for (j, cb) in rhs.coefficients.iter().enumerate() {
                let tmp = ca.mul(cb)?;
                coeffs[i + j] = coeffs[i + j].add(&tmp)?;
            }
        }
        Self::new(curve_type, coeffs)
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
    /// This uses Horner's method: <https://en.wikipedia.org/wiki/Horner%27s_method>
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
        minus_s0 = minus_s0.negate();
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

            if inv.is_zero() {
                return Err(ThresholdEcdsaError::InterpolationError);
            }

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
            base = base.mul(&Polynomial::new(curve, vec![x.negate(), one])?)?;
        }
        Ok(poly)
    }
}

#[derive(Copy, Clone, Serialize, Deserialize)]
pub enum CommitmentOpening {
    Simple(EccScalar),
    Pedersen(EccScalar, EccScalar),
}

impl CommitmentOpening {
    pub fn open_dealing(
        verified_dealing: &IDkgDealingInternal,
        associated_data: &[u8],
        dealer_index: NodeIndex,
        opener_index: NodeIndex,
        opener_secret_key: &MEGaPrivateKey,
        opener_public_key: &MEGaPublicKey,
    ) -> ThresholdEcdsaResult<Self> {
        verified_dealing.ciphertext.decrypt_and_check(
            &verified_dealing.commitment,
            associated_data,
            dealer_index,
            opener_index,
            opener_secret_key,
            opener_public_key,
        )
    }

    pub fn serialize(&self) -> ThresholdEcdsaResult<Vec<u8>> {
        serde_cbor::to_vec(self)
            .map_err(|e| ThresholdEcdsaError::SerializationError(format!("{}", e)))
    }

    pub fn deserialize(bytes: &[u8]) -> ThresholdEcdsaResult<Self> {
        serde_cbor::from_slice::<Self>(bytes)
            .map_err(|e| ThresholdEcdsaError::SerializationError(format!("{}", e)))
    }
}

impl Debug for CommitmentOpening {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::Simple(EccScalar::K256(_)) => {
                write!(f, "CommitmentOpening::Simple(K256(REDACTED))")
            }
            Self::Simple(EccScalar::P256(_)) => {
                write!(f, "CommitmentOpening::Simple(P256(REDACTED))")
            }
            Self::Pedersen(EccScalar::K256(_), EccScalar::K256(_)) => write!(
                f,
                "CommitmentOpening::Pedersen(K256(REDACTED), K256(REDACTED))"
            ),
            Self::Pedersen(EccScalar::P256(_), EccScalar::P256(_)) => write!(
                f,
                "CommitmentOpening::Pedersen(P256(REDACTED), P256(REDACTED))"
            ),
            Self::Pedersen(_, _) => write!(
                f,
                "ERROR: Unsupported curve combination in CommitmentOpening!"
            ),
        }
    }
}

impl TryFrom<&CommitmentOpeningBytes> for CommitmentOpening {
    type Error = ThresholdEcdsaError;

    fn try_from(bytes: &CommitmentOpeningBytes) -> Result<Self, ThresholdEcdsaError> {
        match bytes {
            CommitmentOpeningBytes::Simple(scalar_bytes) => {
                Ok(Self::Simple(EccScalar::try_from(scalar_bytes)?))
            }
            CommitmentOpeningBytes::Pedersen(scalar_bytes_1, scalar_bytes_2) => Ok(Self::Pedersen(
                EccScalar::try_from(scalar_bytes_1)?,
                EccScalar::try_from(scalar_bytes_2)?,
            )),
        }
    }
}

impl TryFrom<&IDkgOpening> for CommitmentOpening {
    type Error = ThresholdEcdsaError;

    fn try_from(idkg_opening: &IDkgOpening) -> Result<Self, ThresholdEcdsaError> {
        Self::deserialize(&idkg_opening.internal_opening_raw)
    }
}

#[derive(Clone, Eq, PartialEq, Zeroize, Serialize, Deserialize)]
#[zeroize(drop)]
pub enum CommitmentOpeningBytes {
    Simple(EccScalarBytes),
    Pedersen(EccScalarBytes, EccScalarBytes),
}

impl TryFrom<&CommitmentOpening> for CommitmentOpeningBytes {
    type Error = ThresholdEcdsaError;

    fn try_from(commitment_opening: &CommitmentOpening) -> Result<Self, ThresholdEcdsaError> {
        match commitment_opening {
            CommitmentOpening::Simple(scalar) => {
                Ok(Self::Simple(EccScalarBytes::try_from(scalar)?))
            }
            CommitmentOpening::Pedersen(scalar_1, scalar_2) => Ok(Self::Pedersen(
                EccScalarBytes::try_from(scalar_1)?,
                EccScalarBytes::try_from(scalar_2)?,
            )),
        }
    }
}

/// A simple (discrete log) commitment to a polynomial
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SimpleCommitment {
    pub points: Vec<EccPoint>,
}

fn evaluate_at(points: &[EccPoint], eval_point: NodeIndex) -> ThresholdEcdsaResult<EccPoint> {
    let curve_type = points[0].curve_type();

    let mut acc = EccPoint::identity(curve_type);
    for pt in points.iter().rev() {
        acc = acc.mul_by_node_index(eval_point)?;
        acc = acc.add_points(pt)?;
    }
    Ok(acc)
}

impl SimpleCommitment {
    pub(crate) fn new(points: Vec<EccPoint>) -> Self {
        Self { points }
    }

    pub fn constant_term(&self) -> EccPoint {
        self.points[0]
    }

    /// Create a new simple commitment
    ///
    /// The polynomial must have at most num_coefficients coefficients
    pub fn create(poly: &Polynomial, num_coefficients: usize) -> ThresholdEcdsaResult<Self> {
        if poly.non_zero_coefficients() > num_coefficients {
            return Err(ThresholdEcdsaError::InvalidArguments(
                "Polynomial has more coefficients than expected".to_string(),
            ));
        }

        let mut points = Vec::with_capacity(num_coefficients);

        for i in 0..num_coefficients {
            points.push(EccPoint::mul_by_g(&poly.coeff(i))?);
        }

        Ok(Self::new(points))
    }

    pub(crate) fn evaluate_at(&self, eval_point: NodeIndex) -> ThresholdEcdsaResult<EccPoint> {
        evaluate_at(&self.points, eval_point)
    }

    pub(crate) fn check_opening(
        &self,
        eval_point: NodeIndex,
        value: &EccScalar,
    ) -> ThresholdEcdsaResult<bool> {
        let eval = self.evaluate_at(eval_point)?;
        Ok(eval == EccPoint::mul_by_g(value)?)
    }
}

/// A Pederson commitment to a polynomial
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PedersenCommitment {
    pub points: Vec<EccPoint>,
}

impl PedersenCommitment {
    pub(crate) fn new(points: Vec<EccPoint>) -> Self {
        Self { points }
    }

    pub fn constant_term(&self) -> EccPoint {
        self.points[0]
    }

    /// Create a new Pedersen commitment
    ///
    /// Both polynomials must have at most num_coefficients coefficients.
    /// The masking polynomial should be randomly generated with a secure
    /// random number generator.
    pub fn create(
        p_values: &Polynomial,
        p_masking: &Polynomial,
        num_coefficients: usize,
    ) -> ThresholdEcdsaResult<Self> {
        if p_values.curve_type() != p_masking.curve_type() {
            return Err(ThresholdEcdsaError::CurveMismatch);
        }

        if p_values.non_zero_coefficients() > num_coefficients
            || p_masking.non_zero_coefficients() > num_coefficients
        {
            return Err(ThresholdEcdsaError::InvalidArguments(
                "Polynomial has more coefficients than expected".to_string(),
            ));
        }

        let mut points = Vec::with_capacity(num_coefficients);

        for i in 0..num_coefficients {
            // compute c = g*a + h*b
            let c = EccPoint::pedersen(&p_values.coeff(i), &p_masking.coeff(i))?;
            points.push(c);
        }

        Ok(Self::new(points))
    }

    pub(crate) fn evaluate_at(&self, eval_point: NodeIndex) -> ThresholdEcdsaResult<EccPoint> {
        evaluate_at(&self.points, eval_point)
    }

    pub(crate) fn check_opening(
        &self,
        eval_point: NodeIndex,
        value: &EccScalar,
        mask: &EccScalar,
    ) -> ThresholdEcdsaResult<bool> {
        let eval = self.evaluate_at(eval_point)?;
        Ok(eval == EccPoint::pedersen(value, mask)?)
    }
}

/// The type of a commitment to a polynomial
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PolynomialCommitmentType {
    Simple,
    Pedersen,
}

/// Some type of commitment to a polynomial
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolynomialCommitment {
    Simple(SimpleCommitment),
    Pedersen(PedersenCommitment),
}

impl From<SimpleCommitment> for PolynomialCommitment {
    fn from(c: SimpleCommitment) -> Self {
        Self::Simple(c)
    }
}

impl From<PedersenCommitment> for PolynomialCommitment {
    fn from(c: PedersenCommitment) -> Self {
        Self::Pedersen(c)
    }
}

impl PolynomialCommitment {
    pub fn serialize(&self) -> ThresholdEcdsaResult<Vec<u8>> {
        serde_cbor::to_vec(self)
            .map_err(|e| ThresholdEcdsaError::SerializationError(format!("{}", e)))
    }

    pub fn deserialize(bytes: &[u8]) -> ThresholdEcdsaResult<Self> {
        serde_cbor::from_slice::<Self>(bytes)
            .map_err(|e| ThresholdEcdsaError::SerializationError(format!("{}", e)))
    }

    /// This returns a stable serialization of the commitment
    ///
    /// This encoding is incompatible with the CBOR serialization used
    /// by serialize. It is used to compute key IDs for the SKS so no
    /// equivalent deserialization function is provided. For this
    /// reason the encoding *must never change* in the future as this
    /// would prevent looking up existing openings in the SKS
    pub fn to_bytes(&self) -> Vec<u8> {
        let curve_type = self.curve_type();
        let mut r = Vec::with_capacity(2 + self.len() * curve_type.point_bytes());

        let commitment_tag = match self.ctype() {
            PolynomialCommitmentType::Simple => b'S',
            PolynomialCommitmentType::Pedersen => b'P',
        };

        r.push(commitment_tag);
        r.push(curve_type.tag());

        for point in self.points() {
            r.extend_from_slice(&point.serialize());
        }

        r
    }

    pub(crate) fn ctype(&self) -> PolynomialCommitmentType {
        match self {
            Self::Simple(_) => PolynomialCommitmentType::Simple,
            Self::Pedersen(_) => PolynomialCommitmentType::Pedersen,
        }
    }

    pub(crate) fn points(&self) -> &[EccPoint] {
        match self {
            Self::Simple(c) => &c.points,
            Self::Pedersen(c) => &c.points,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.points().len()
    }

    pub(crate) fn evaluate_at(&self, eval_point: NodeIndex) -> ThresholdEcdsaResult<EccPoint> {
        evaluate_at(self.points(), eval_point)
    }

    pub fn constant_term(&self) -> EccPoint {
        self.points()[0]
    }

    pub fn curve_type(&self) -> EccCurveType {
        self.constant_term().curve_type()
    }

    pub(crate) fn return_opening_if_consistent(
        &self,
        index: NodeIndex,
        opening: &CommitmentOpening,
    ) -> ThresholdEcdsaResult<CommitmentOpening> {
        if self.check_opening(index, opening)? {
            Ok(*opening)
        } else {
            Err(ThresholdEcdsaError::InvalidCommitment)
        }
    }

    pub fn verify_is(
        &self,
        ctype: PolynomialCommitmentType,
        curve: EccCurveType,
    ) -> ThresholdEcdsaResult<()> {
        if self.curve_type() != curve {
            return Err(ThresholdEcdsaError::CurveMismatch);
        }

        if self.ctype() != ctype {
            return Err(ThresholdEcdsaError::UnexpectedCommitmentType);
        }

        Ok(())
    }

    pub fn check_opening(
        &self,
        eval_point: NodeIndex,
        opening: &CommitmentOpening,
    ) -> ThresholdEcdsaResult<bool> {
        match (self, opening) {
            (PolynomialCommitment::Simple(c), CommitmentOpening::Simple(value)) => {
                c.check_opening(eval_point, value)
            }

            (PolynomialCommitment::Pedersen(c), CommitmentOpening::Pedersen(value, mask)) => {
                c.check_opening(eval_point, value, mask)
            }

            _ => Err(ThresholdEcdsaError::InvalidOpening),
        }
    }
}

pub struct LagrangeCoefficients {
    coefficients: Vec<EccScalar>,
}

impl LagrangeCoefficients {
    fn new(coefficients: Vec<EccScalar>) -> ThresholdEcdsaResult<Self> {
        if coefficients.is_empty() {
            return Err(ThresholdEcdsaError::InterpolationError);
        }

        Ok(Self { coefficients })
    }

    pub fn coefficients(&self) -> &[EccScalar] {
        &self.coefficients
    }

    /// Given a list of samples `(x, f(x) * g)` for a set of unique `x`, some
    /// polynomial `f`, and some elliptic curve point `g`, returns `f(value) * g`.
    ///
    /// See: <https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach>
    pub fn interpolate_point(&self, y: &[EccPoint]) -> ThresholdEcdsaResult<EccPoint> {
        if y.len() != self.coefficients.len() {
            return Err(ThresholdEcdsaError::InterpolationError);
        }
        let curve_type = self.coefficients[0].curve_type();
        let mut result = EccPoint::identity(curve_type);
        for (coefficient, sample) in self.coefficients.iter().zip(y) {
            result = result.add_points(&sample.scalar_mul(coefficient)?)?;
        }
        Ok(result)
    }

    /// Given a list of samples `(x, f(x))` for a set of unique `x`, some
    /// polynomial `f`, returns `f(value) * g`.
    ///
    /// See: <https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach>
    pub fn interpolate_scalar(&self, y: &[EccScalar]) -> ThresholdEcdsaResult<EccScalar> {
        if y.len() != self.coefficients.len() {
            return Err(ThresholdEcdsaError::InterpolationError);
        }
        let curve_type = self.coefficients[0].curve_type();
        let mut result = EccScalar::zero(curve_type);
        for (coefficient, sample) in self.coefficients.iter().zip(y) {
            result = result.add(&sample.mul(coefficient)?)?;
        }
        Ok(result)
    }

    /// Check for duplicate dealer indexes
    ///
    /// Since these are public we don't need to worry about the lack of constant
    /// time behavior from HashSet
    fn check_for_duplicates(node_index: &[NodeIndex]) -> ThresholdEcdsaResult<()> {
        let mut set = std::collections::HashSet::new();

        for i in node_index {
            if !set.insert(i) {
                return Err(ThresholdEcdsaError::InterpolationError);
            }
        }

        Ok(())
    }

    /// Computes Lagrange polynomials evaluated at zero
    ///
    /// Namely it computes the following values:
    ///    * lagrange_i = numerator_i/denominator_i
    ///    * numerator_i = (x_0) * (x_1) * ... * (x_(i-1)) *(x_(i+1)) * ... *(x_n)
    ///    * denominator_i = (x_0 - x_i) * (x_1 - x_i) * ... * (x_(i-1) - x_i) *
    ///      (x_(i+1) - x_i) * ... * (x_n - x_i)
    pub fn at_zero(
        curve_type: EccCurveType,
        samples: &[NodeIndex],
    ) -> Result<Self, ThresholdEcdsaError> {
        Self::at_value(&EccScalar::zero(curve_type), samples)
    }

    /// Computes Lagrange polynomials evaluated at a given value.
    ///
    /// Namely it computes the following values:
    ///    * lagrange_i = numerator_i/denominator_i
    ///    * numerator_i = (x_0-value) * (x_1-value) * ... * (x_(i-1)-value) *(x_(i+1)-value) * ... *(x_n-value)
    ///    * denominator_i = (x_0 - x_i) * (x_1 - x_i) * ... * (x_(i-1) - x_i) *
    ///      (x_(i+1) - x_i) * ... * (x_n - x_i)
    pub fn at_value(value: &EccScalar, samples: &[NodeIndex]) -> Result<Self, ThresholdEcdsaError> {
        // This is not strictly required but for our usage it simplifies matters
        if samples.is_empty() {
            return Err(ThresholdEcdsaError::InterpolationError);
        }

        let curve_type = value.curve_type();

        if samples.len() == 1 {
            return Self::new(vec![EccScalar::one(curve_type)]);
        }

        Self::check_for_duplicates(samples)?;

        let samples: Vec<EccScalar> = samples
            .iter()
            .map(|s| EccScalar::from_node_index(curve_type, *s))
            .collect();

        let mut numerator = Vec::with_capacity(samples.len());
        let mut tmp = EccScalar::one(curve_type);
        numerator.push(tmp);
        for x in samples.iter().take(samples.len() - 1) {
            tmp = tmp.mul(&x.sub(value)?)?;
            numerator.push(tmp);
        }

        tmp = EccScalar::one(curve_type);
        for (i, x) in samples[1..].iter().enumerate().rev() {
            tmp = tmp.mul(&x.sub(value)?)?;
            numerator[i] = numerator[i].mul(&tmp)?;
        }

        for (lagrange_i, x_i) in numerator.iter_mut().zip(&samples) {
            // Compute the value at 0 of the i-th Lagrange polynomial that is `0` at the
            // other data points but `1` at `x_i`.
            let mut denom = EccScalar::one(curve_type);
            for x_j in samples.iter().filter(|x_j| *x_j != x_i) {
                let diff = x_j.sub(x_i)?;
                denom = denom.mul(&diff)?;
            }
            let inv = denom.invert()?;

            if inv.is_zero() {
                return Err(ThresholdEcdsaError::InterpolationError);
            }

            *lagrange_i = lagrange_i.mul(&inv)?;
        }
        Self::new(numerator)
    }
}
