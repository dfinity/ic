use crate::CspPublicKey;
use hex::FromHex;
use ic_crypto_internal_threshold_sig_ecdsa::{EccCurveType, MEGaPublicKey, PolynomialCommitment};
use ic_crypto_internal_types::encrypt::forward_secure::CspFsEncryptionPublicKey;
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::CspPublicCoefficients;
use ic_crypto_sha2::{Context, DomainSeparationContext, Sha256};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::{AlgorithmId, CryptoError};
use std::fmt;
use std::fmt::Formatter;

const KEY_ID_DOMAIN: &str = "ic-key-id";
const COMMITMENT_KEY_ID_DOMAIN: &str = "ic-key-id-idkg-commitment";
const THRESHOLD_PUBLIC_COEFFICIENTS_KEY_ID_DOMAIN: &str =
    "KeyId from threshold public coefficients";
const KEY_ID_PREFIX: &str = "KeyId(0x";
const KEY_ID_SUFFIX: &str = ")";

#[cfg(test)]
mod tests;

/// An id of a key. These ids are used to refer to entries in the crypto secret
/// key store.
///
/// # System Invariant
/// It is a critical system invariant that the generated `KeyId` remains stable.
/// This means that the same inputs should *always* produce instances of `KeyId` with the same value.
/// This should be ensured via testing, especially if an external library is involved in generating those inputs.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct KeyId([u8; 32]);
ic_crypto_internal_types::derive_serde!(KeyId, 32);

impl KeyId {
    pub fn get(&self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            KEY_ID_PREFIX,
            hex::encode(self.0),
            KEY_ID_SUFFIX
        )
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<[u8; 32]> for KeyId {
    fn from(bytes: [u8; 32]) -> Self {
        KeyId(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum KeyIdInstantiationError {
    InvalidArguments(String),
}

impl From<KeyIdInstantiationError> for CryptoError {
    fn from(error: KeyIdInstantiationError) -> Self {
        CryptoError::InvalidArgument {
            message: format!("Cannot instantiate KeyId: {:?}", error),
        }
    }
}

/// Compute a KeyId from an `AlgorithmId` and a slice of bytes.
///
/// The computed KeyId is the result of applying SHA256 to the bytes:
/// `domain_separator | algorithm_id | size(bytes) | bytes`
/// where  domain_separator is DomainSeparationContext(KEY_ID_DOMAIN),
/// algorithm_id is a 1-byte value, and size(pk_bytes) is the size of
/// pk_bytes as u32 in BigEndian format.
///
/// # Errors
/// * `KeyIdInstantiationError::InvalidArgument`: if the slice of bytes is too large and its size does not fit in a `u32`.
impl<B> TryFrom<(AlgorithmId, &B)> for KeyId
where
    B: AsRef<[u8]>,
{
    type Error = KeyIdInstantiationError;

    fn try_from((alg_id, bytes): (AlgorithmId, &B)) -> Result<Self, Self::Error> {
        let bytes = bytes.as_ref();
        let bytes_size = u32::try_from(bytes.len()).map_err(|_error| {
            KeyIdInstantiationError::InvalidArguments(format!(
                "Bytes array is too large (number of bytes {} does not fit in a u32)",
                bytes.len()
            ))
        })?;
        let mut hash =
            Sha256::new_with_context(&DomainSeparationContext::new(KEY_ID_DOMAIN.to_string()));
        hash.write(&[u8::from(alg_id)]);
        hash.write(&bytes_size.to_be_bytes());
        hash.write(bytes);
        Ok(KeyId::from(hash.finish()))
    }
}

impl TryFrom<&CspPublicKey> for KeyId {
    type Error = KeyIdInstantiationError;

    fn try_from(public_key: &CspPublicKey) -> Result<Self, Self::Error> {
        KeyId::try_from((public_key.algorithm_id(), &public_key.pk_bytes()))
    }
}

impl TryFrom<&MEGaPublicKey> for KeyId {
    type Error = String;

    fn try_from(public_key: &MEGaPublicKey) -> Result<Self, Self::Error> {
        match public_key.curve_type() {
            EccCurveType::K256 => KeyId::try_from((
                AlgorithmId::ThresholdEcdsaSecp256k1,
                &public_key.serialize(),
            ))
            .map_err(|error| format!("cannot instantiate KeyId: {:?}", error)),
            c => Err(format!("unsupported curve: {:?}", c)),
        }
    }
}

impl From<&CspFsEncryptionPublicKey> for KeyId {
    fn from(public_key: &CspFsEncryptionPublicKey) -> Self {
        let mut hash = Sha256::new_with_context(&DomainSeparationContext::new(
            "KeyId from CspFsEncryptionPublicKey",
        ));
        let variant: &'static str = public_key.into();
        hash.write(DomainSeparationContext::new(variant).as_bytes());
        match public_key {
            CspFsEncryptionPublicKey::Groth20_Bls12_381(public_key) => {
                hash.write(public_key.as_bytes())
            }
        }
        KeyId::from(hash.finish())
    }
}

impl From<&PolynomialCommitment> for KeyId {
    fn from(commitment: &PolynomialCommitment) -> Self {
        let mut hash =
            Sha256::new_with_context(&DomainSeparationContext::new(COMMITMENT_KEY_ID_DOMAIN));
        let commitment_encoding = commitment.stable_representation();
        hash.write(&(commitment_encoding.len() as u64).to_be_bytes());
        hash.write(&commitment_encoding);
        KeyId::from(hash.finish())
    }
}

impl TryFrom<&TlsPublicKeyCert> for KeyId {
    type Error = KeyIdInstantiationError;

    fn try_from(cert: &TlsPublicKeyCert) -> Result<Self, Self::Error> {
        KeyId::try_from((AlgorithmId::Tls, cert.as_der()))
    }
}

impl TryFrom<&CspPublicCoefficients> for KeyId {
    type Error = KeyIdInstantiationError;

    fn try_from(coefficients: &CspPublicCoefficients) -> Result<Self, Self::Error> {
        let mut hash = Sha256::new_with_context(&DomainSeparationContext::new(
            THRESHOLD_PUBLIC_COEFFICIENTS_KEY_ID_DOMAIN,
        ));
        hash.write(&serde_cbor::to_vec(&coefficients).map_err(|err| {
            Self::Error::InvalidArguments(format!(
                "Failed to serialize public coefficients: {}",
                err
            ))
        })?);
        Ok(KeyId::from(hash.finish()))
    }
}

impl FromHex for KeyId {
    type Error = String;

    fn from_hex<T: AsRef<[u8]>>(data: T) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = hex::decode(data)
            .map_err(|err| format!("Error decoding hex: {}", err))?
            .try_into()
            .map_err(|_err| "wrong size of array: expected 32 bytes")?;
        Ok(KeyId::from(bytes))
    }
}

impl AsRef<[u8]> for KeyId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
