//! Public counterpart to a polynomial.

use crate::crypto::public_key_from_secret_key;
use crate::types::{Polynomial, PublicKey, ThresholdError};
use ic_crypto_internal_bls12_381_type::{
    G1Projective, G2Projective, LagrangeCoefficients, NodeIndex, NodeIndices, Scalar,
};
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::CspPublicCoefficients;
pub use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes as InternalPublicCoefficients;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::{
    PublicKeyBytes, ThresholdSigPublicKeyBytesConversionError,
};
use ic_types::NumberOfNodes;
use ic_types::crypto::{CryptoError, CryptoResult};
use std::convert::TryFrom;

/// Given a polynomial with secret coefficients <a0, ..., ak> the public
/// coefficients are the public keys <A0, ..., Ak> corresponding to those secret
/// keys.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct PublicCoefficients {
    pub coefficients: Vec<PublicKey>,
}

impl PublicCoefficients {
    /// Returns the empty vector
    pub fn zero() -> Self {
        Self {
            coefficients: vec![],
        }
    }

    pub(crate) fn new(coefficients: Vec<PublicKey>) -> Self {
        Self { coefficients }
    }

    /// Deserializes a `PublicCoefficients` from a *trusted* source.
    ///
    /// # Note
    /// This caches the deserialized points with the expectation that
    /// at least some of the points will be seen again.
    pub fn deserialize_cached(
        bytes: &InternalPublicCoefficients,
    ) -> Result<PublicCoefficients, CryptoError> {
        let coefficients: Result<Vec<PublicKey>, ThresholdSigPublicKeyBytesConversionError> = bytes
            .coefficients
            .iter()
            .map(PublicKey::deserialize_cached)
            .collect();
        let coefficients = coefficients?;
        Ok(PublicCoefficients { coefficients })
    }

    /// Evaluate the public coefficients at x
    pub fn evaluate_at(&self, x: &Scalar) -> G2Projective {
        let mut coefficients = self.coefficients.iter().rev();
        let first = coefficients.next().map(|pk| pk.0.clone());
        match first {
            None => G2Projective::identity(),
            Some(ans) => {
                let mut ans: G2Projective = ans;
                for coeff in coefficients {
                    ans *= x;
                    ans += &coeff.0;
                }
                ans
            }
        }
    }

    /// Given a list of samples `(x, f(x) * g)` for a polynomial `f` in the scalar field, and a generator g of G1 returns
    /// `f(0) * g`.
    /// See: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach
    /// # Arguments:
    /// * `samples` contains the list of `(x, y)` points to be used in the interpolation, where `x` is an element in the scalar field, and the `y` is an element of G1.
    /// # Returns
    /// The generator `g` of G1 multiplied by to the constant term of the interpolated polynomial `f(x)`. If `samples` contains multiple entries for the same scalar `x`, only the first sample contributes toward the interpolation and the subsequent entries are discarded.
    pub fn interpolate_g1(
        samples: &[(NodeIndex, G1Projective)],
    ) -> Result<G1Projective, ThresholdError> {
        let all_x: Vec<NodeIndex> = samples.iter().map(|(x, _)| *x).collect();
        let coefficients = Self::lagrange_coefficients_at_zero(&all_x)?;
        let pts: Vec<_> = samples.iter().map(|(_, pt)| pt.clone()).collect();
        Ok(G1Projective::muln_vartime(&pts, &coefficients))
    }

    /// Given a list of samples `(x, f(x) * g)` for a polynomial `f` in the scalar field, and a generator g of G2 returns
    /// `f(0) * g`.
    /// See: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing#Computationally_efficient_approach
    /// # Arguments:
    /// * `samples` contains the list of `(x, y)` points to be used in the interpolation, where `x` is an element in the scalar field, and the `y` is an element of G2.
    /// # Returns
    /// The generator `g` of G2 multiplied by to the constant term of the interpolated polynomial `f(x)`, i.e. `f(0)`. If `samples` contains multiple entries for the same scalar `x`, only the first sample contributes toward the interpolation and the subsequent entries are discarded.
    pub fn interpolate_g2(
        samples: &[(NodeIndex, G2Projective)],
    ) -> Result<G2Projective, ThresholdError> {
        let all_x: Vec<NodeIndex> = samples.iter().map(|(x, _)| *x).collect();
        let coefficients = Self::lagrange_coefficients_at_zero(&all_x)?;
        let pts: Vec<_> = samples.iter().map(|(_, pt)| pt.clone()).collect();
        Ok(G2Projective::muln_vartime(&pts, &coefficients))
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
    /// `ThresholdError::DuplicateX`: in case the interpolation points `samples` are not all distinct.
    pub fn lagrange_coefficients_at_zero(
        samples: &[NodeIndex],
    ) -> Result<Vec<Scalar>, ThresholdError> {
        if samples.is_empty() {
            return Ok(Vec::new());
        }

        let indices = NodeIndices::from_slice(samples).map_err(|_| ThresholdError::DuplicateX)?;

        Ok(LagrangeCoefficients::at_zero(&indices)
            .coefficients()
            .to_vec())
    }

    pub(super) fn remove_zeros(&mut self) {
        let zeros = self
            .coefficients
            .iter()
            .rev()
            .take_while(|c| c.0.is_identity())
            .count();
        let len = self.coefficients.len() - zeros;
        self.coefficients.truncate(len)
    }
}

impl<B: std::borrow::Borrow<PublicCoefficients>> std::iter::Sum<B> for PublicCoefficients {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = B>,
    {
        iter.fold(PublicCoefficients::zero(), |a, b| a + b)
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl<B: std::borrow::Borrow<PublicCoefficients>> std::ops::AddAssign<B> for PublicCoefficients {
    fn add_assign(&mut self, rhs: B) {
        let len = self.coefficients.len();
        let rhs_len = rhs.borrow().coefficients.len();
        if rhs_len > len {
            self.coefficients
                .resize(rhs_len, PublicKey(G2Projective::identity()));
        }
        for (self_c, rhs_c) in self.coefficients.iter_mut().zip(&rhs.borrow().coefficients) {
            self_c.0.add_assign(&rhs_c.0);
        }
        self.remove_zeros();
    }
}

impl<B: std::borrow::Borrow<PublicCoefficients>> std::ops::Add<B> for PublicCoefficients {
    type Output = Self;

    fn add(mut self, rhs: B) -> Self {
        self += rhs;
        self
    }
}

fn invalid_size(error: std::num::TryFromIntError) -> CryptoError {
    CryptoError::InvalidArgument {
        message: format!("{error:?}"),
    }
}

impl TryFrom<&PublicCoefficients> for NumberOfNodes {
    type Error = CryptoError;
    fn try_from(public_coefficients: &PublicCoefficients) -> CryptoResult<Self> {
        let size = public_coefficients.coefficients.len();
        let size = NodeIndex::try_from(size).map_err(invalid_size)?;
        Ok(NumberOfNodes::from(size))
    }
}

/// Returns the length of the given `public_coefficients` as a `NumberOfNodes`.
///
/// # Errors
/// * `CryptoError::InvalidArgument` if the `len` of the given
///   `public_coefficients` cannot be converted to a `NodeIndex`.
pub fn try_number_of_nodes_from_pub_coeff_bytes(
    public_coefficients: &PublicCoefficientsBytes,
) -> CryptoResult<NumberOfNodes> {
    let len = public_coefficients.coefficients.len();
    let len = NodeIndex::try_from(len).map_err(invalid_size)?;
    Ok(NumberOfNodes::from(len))
}

/// Returns the length of the given `CspPublicCoefficients` as a
/// `NumberOfNodes`.
///
/// Cf. `try_number_of_nodes_from_pub_coeff_bytes`.
///
/// Used only for testing.
pub fn try_number_of_nodes_from_csp_pub_coeffs(
    value: &CspPublicCoefficients,
) -> CryptoResult<NumberOfNodes> {
    match value {
        CspPublicCoefficients::Bls12_381(public_coefficients) => {
            try_number_of_nodes_from_pub_coeff_bytes(public_coefficients)
        }
    }
}

impl From<&Polynomial> for PublicCoefficients {
    fn from(polynomial: &Polynomial) -> Self {
        PublicCoefficients {
            coefficients: polynomial
                .coefficients()
                .iter()
                .map(public_key_from_secret_key)
                .collect(),
        }
    }
}

impl From<Polynomial> for PublicCoefficients {
    fn from(polynomial: Polynomial) -> Self {
        PublicCoefficients::from(&polynomial)
    }
}

impl From<&PublicCoefficients> for PublicKey {
    fn from(public_coefficients: &PublicCoefficients) -> Self {
        // Empty public_coefficients represent an all-zero polynomial,
        // so in this case we return a zero-public key.
        public_coefficients
            .coefficients
            .first()
            .cloned()
            .unwrap_or_else(|| PublicKey(G2Projective::identity()))
    }
}

impl TryFrom<&PublicCoefficientsBytes> for PublicKey {
    type Error = CryptoError;
    fn try_from(public_coefficients: &PublicCoefficientsBytes) -> Result<Self, CryptoError> {
        // Empty public_coefficients represent an all-zero polynomial,
        // so in this case we return a zero-public key.
        Ok(public_coefficients
            .coefficients
            .first()
            .map(PublicKey::try_from)
            .unwrap_or_else(|| Ok(PublicKey(G2Projective::identity())))?)
    }
}

/// Returns the public key associated to the given `public_coefficients`.
///
/// Empty public_coefficients represent an all-zero polynomial,
/// so in this case we return a zero-public key.
pub fn pub_key_bytes_from_pub_coeff_bytes(
    public_coefficients: &PublicCoefficientsBytes,
) -> PublicKeyBytes {
    public_coefficients
        .coefficients
        .first()
        .cloned()
        .unwrap_or_else(|| PublicKeyBytes::from(PublicKey(G2Projective::identity())))
}

// The internal PublicCoefficients are a duplicate of InternalPublicCoefficients
impl From<&PublicCoefficients> for InternalPublicCoefficients {
    fn from(public_coefficients: &PublicCoefficients) -> Self {
        InternalPublicCoefficients {
            coefficients: public_coefficients
                .coefficients
                .iter()
                .map(PublicKeyBytes::from)
                .collect::<Vec<PublicKeyBytes>>(),
        }
    }
}

impl From<PublicCoefficients> for InternalPublicCoefficients {
    fn from(public_coefficients: PublicCoefficients) -> Self {
        InternalPublicCoefficients::from(&public_coefficients)
    }
}

impl TryFrom<&InternalPublicCoefficients> for PublicCoefficients {
    type Error = CryptoError;
    fn try_from(bytes: &InternalPublicCoefficients) -> Result<PublicCoefficients, CryptoError> {
        let coefficients: Result<Vec<PublicKey>, ThresholdSigPublicKeyBytesConversionError> =
            bytes.coefficients.iter().map(PublicKey::try_from).collect();
        let coefficients = coefficients?;
        Ok(PublicCoefficients { coefficients })
    }
}
