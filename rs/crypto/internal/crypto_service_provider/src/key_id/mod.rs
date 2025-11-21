use crate::CspPublicKey;
use hex::FromHex;
use ic_crypto_internal_threshold_sig_canister_threshold_sig::{
    EccCurveType, MEGaPublicKey, PolynomialCommitment,
};
use ic_crypto_internal_types::encrypt::forward_secure::CspFsEncryptionPublicKey;
use ic_crypto_internal_types::sign::threshold_sig::public_coefficients::CspPublicCoefficients;
use ic_crypto_sha2::{DomainSeparationContext, Sha256};
use ic_crypto_tls_interfaces::TlsPublicKeyCert;
use ic_types::crypto::AlgorithmId;
use std::fmt;
use std::fmt::Formatter;

const KEY_ID_DOMAIN: &str = "ic-key-id";
const KEY_ID_LARGE_DOMAIN: &str = "ic-key-id-large";
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
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
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
        write!(f, "{self:?}")
    }
}

impl From<[u8; 32]> for KeyId {
    fn from(bytes: [u8; 32]) -> Self {
        KeyId(bytes)
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum KeyIdInstantiationError {
    InvalidArguments(String),
}

/// Compute a KeyId from an `AlgorithmId` and a slice of bytes.
impl<B: AsRef<[u8]>> From<(AlgorithmId, &B)> for KeyId {
    fn from((alg_id, bytes): (AlgorithmId, &B)) -> Self {
        let bytes = bytes.as_ref();
        match u32::try_from(bytes.len()) {
            Ok(bytes_size_u32) => {
                // bytes < 4 GiB (==u32::MAX==2^32-1)
                let dom_sep = DomainSeparationContext::new(KEY_ID_DOMAIN.to_string());
                let mut hash = Sha256::new_with_context(&dom_sep);
                hash.write(&[u8::from(alg_id)]); // 1 byte
                hash.write(&bytes_size_u32.to_be_bytes()); // 4 bytes
                hash.write(bytes);
                KeyId::from(hash.finish())
            }
            Err(_) => {
                match u64::try_from(bytes.len()) {
                    Ok(bytes_size_u64) => {
                        // 4 GiB <= bytes < 16384 PiB (==u64::MAX==2^64-1)
                        let dom_sep = DomainSeparationContext::new(KEY_ID_LARGE_DOMAIN.to_string());
                        let mut hash = Sha256::new_with_context(&dom_sep);
                        hash.write(&[u8::from(alg_id)]); // 1 byte
                        hash.write(&bytes_size_u64.to_be_bytes()); // 8 bytes
                        hash.write(bytes);
                        KeyId::from(hash.finish())
                    }
                    Err(_) => {
                        // bytes >= 16384 PiB (==u64::MAX==2^64-1)
                        // It is very reasonable to panic here
                        panic!("bytes >= 16384 PiB (=2^64-1)")
                    }
                }
            }
        }
    }
}

impl From<&CspPublicKey> for KeyId {
    fn from(public_key: &CspPublicKey) -> Self {
        KeyId::from((AlgorithmId::from(public_key), public_key))
    }
}

impl TryFrom<&MEGaPublicKey> for KeyId {
    type Error = String;

    fn try_from(public_key: &MEGaPublicKey) -> Result<Self, Self::Error> {
        match public_key.curve_type() {
            EccCurveType::K256 => Ok(KeyId::from((
                AlgorithmId::ThresholdEcdsaSecp256k1,
                &public_key.serialize(),
            ))),
            c => Err(format!("unsupported curve: {c:?}")),
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

impl From<&TlsPublicKeyCert> for KeyId {
    fn from(cert: &TlsPublicKeyCert) -> Self {
        KeyId::from((AlgorithmId::Tls, cert.as_der()))
    }
}

impl TryFrom<&CspPublicCoefficients> for KeyId {
    type Error = KeyIdInstantiationError;

    fn try_from(coefficients: &CspPublicCoefficients) -> Result<Self, Self::Error> {
        let mut hash = Sha256::new_with_context(&DomainSeparationContext::new(
            THRESHOLD_PUBLIC_COEFFICIENTS_KEY_ID_DOMAIN,
        ));
        hash.write(&serde_cbor::to_vec(&coefficients).map_err(|err| {
            Self::Error::InvalidArguments(format!("Failed to serialize public coefficients: {err}"))
        })?);
        Ok(KeyId::from(hash.finish()))
    }
}

impl FromHex for KeyId {
    type Error = String;

    fn from_hex<T: AsRef<[u8]>>(data: T) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = hex::decode(data)
            .map_err(|err| format!("Error decoding hex: {err}"))?
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
