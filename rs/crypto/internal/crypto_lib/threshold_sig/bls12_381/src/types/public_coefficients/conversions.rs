//! Reasonably simple type conversions.

use crate::crypto::public_key_from_secret_key;
use crate::types::{Polynomial, PublicCoefficients, PublicKey};
use group::CurveProjective;
use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::ni_dkg_groth20_bls12_381::PublicCoefficientsBytes;
pub use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::bls12_381::PublicCoefficientsBytes as InternalPublicCoefficients;
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::CspPublicCoefficients;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::{
    PublicKeyBytes, ThresholdSigPublicKeyBytesConversionError,
};
use ic_types::crypto::{CryptoError, CryptoResult};
use ic_types::{NodeIndex, NumberOfNodes};
use pairing::bls12_381::G2;
use std::convert::TryFrom;

#[cfg(test)]
mod tests;

fn invalid_size(error: std::num::TryFromIntError) -> CryptoError {
    CryptoError::InvalidArgument {
        message: format!("{:?}", error),
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
            try_number_of_nodes_from_pub_coeff_bytes(public_coefficients).map_err(|e| e)
        }
    }
}

impl From<&Polynomial> for PublicCoefficients {
    fn from(polynomial: &Polynomial) -> Self {
        PublicCoefficients {
            coefficients: polynomial
                .coefficients
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
            .get(0)
            .copied()
            .unwrap_or_else(|| PublicKey(G2::zero()))
    }
}

impl TryFrom<&PublicCoefficientsBytes> for PublicKey {
    type Error = CryptoError;
    fn try_from(public_coefficients: &PublicCoefficientsBytes) -> Result<Self, CryptoError> {
        // Empty public_coefficients represent an all-zero polynomial,
        // so in this case we return a zero-public key.
        Ok(public_coefficients
            .coefficients
            .get(0)
            .map(PublicKey::try_from)
            .unwrap_or_else(|| Ok(PublicKey(G2::zero())))?)
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
        .get(0)
        .cloned()
        .unwrap_or_else(|| PublicKeyBytes::from(PublicKey(G2::zero())))
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
