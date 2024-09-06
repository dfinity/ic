use super::*;
use crate::KeyId;
use ic_crypto_internal_threshold_sig_bls12381::api::threshold_sign_error::ClibThresholdSignError;

/// Errors occurring while performing threshold signature generation
#[derive(Clone, Eq, PartialEq, Hash, Debug, Deserialize, Serialize)]
pub enum CspThresholdSignError {
    SecretKeyNotFound {
        algorithm: AlgorithmId,
        key_id: KeyId,
    },
    UnsupportedAlgorithm {
        algorithm: AlgorithmId,
    },
    WrongSecretKeyType {},
    MalformedSecretKey {
        algorithm: AlgorithmId,
    },
    KeyIdInstantiationError(String),
    TransientInternalError {
        internal_error: String,
    },
}

impl From<ClibThresholdSignError> for CspThresholdSignError {
    fn from(clib_error: ClibThresholdSignError) -> Self {
        match clib_error {
            ClibThresholdSignError::MalformedSecretKey { algorithm } => {
                CspThresholdSignError::MalformedSecretKey { algorithm }
            }
        }
    }
}

impl From<CspSecretKeyConversionError> for CspThresholdSignError {
    fn from(sk_conversion_error: CspSecretKeyConversionError) -> Self {
        match sk_conversion_error {
            CspSecretKeyConversionError::WrongSecretKeyType {} => {
                CspThresholdSignError::WrongSecretKeyType {}
            }
        }
    }
}

impl fmt::Display for CspThresholdSignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CspThresholdSignError::SecretKeyNotFound { algorithm, key_id } => write!(
                f,
                "The secret key with key id {:?} and algorithm id {:?} was not found in the \
                secret key store.",
                key_id, algorithm
            ),
            CspThresholdSignError::UnsupportedAlgorithm { algorithm } => write!(
                f,
                "The algorithm of the public key from the threshold signature data \
            store is not supported: {:?}",
                algorithm
            ),
            CspThresholdSignError::WrongSecretKeyType {} => {
                write!(f, "The secret key has a wrong type")
            }
            CspThresholdSignError::MalformedSecretKey { algorithm } => write!(
                f,
                "Unable to parse the secret key with algorithm id {:?}",
                algorithm
            ),
            CspThresholdSignError::TransientInternalError { internal_error } => {
                write!(f, "Transient internal error: {}", internal_error)
            }
            CspThresholdSignError::KeyIdInstantiationError(message) => {
                write!(f, "KeyID instantiation error: {}", message)
            }
        }
    }
}
