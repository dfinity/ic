//! Data types for threshold public keys.
use crate::sign::threshold_sig::ni_dkg::CspNiDkgTranscript;
use serde::{Deserialize, Serialize};
use std::hash::Hash;

/// A threshold signature public key.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialOrd, Ord, PartialEq, Serialize, Deserialize)]
pub enum CspThresholdSigPublicKey {
    ThresBls12_381(bls12_381::PublicKeyBytes),
}

impl From<CspThresholdSigPublicKey> for bls12_381::PublicKeyBytes {
    fn from(pk: CspThresholdSigPublicKey) -> Self {
        match pk {
            CspThresholdSigPublicKey::ThresBls12_381(bytes) => bytes,
        }
    }
}

impl From<&CspNiDkgTranscript> for CspThresholdSigPublicKey {
    // The conversion is deliberately implemented directly, i.e., without
    // using From-conversions involving intermediate types, because the
    // panic on empty coefficients is currently specific to converting
    // the transcript to the contained threshold signature public key.
    fn from(csp_ni_dkg_transcript: &CspNiDkgTranscript) -> Self {
        match csp_ni_dkg_transcript {
            CspNiDkgTranscript::Groth20_Bls12_381(transcript) => Self::ThresBls12_381(
                transcript
                    .public_coefficients
                    .coefficients
                    .get(0)
                    .copied()
                    .expect("coefficients empty"),
            ),
        }
    }
}

impl From<bls12_381::PublicKeyBytes> for CspThresholdSigPublicKey {
    fn from(public_key_bytes: bls12_381::PublicKeyBytes) -> Self {
        CspThresholdSigPublicKey::ThresBls12_381(public_key_bytes)
    }
}

pub mod bls12_381 {
    //! Data types for BLS12-381 threshold signature public keys.
    use super::*;
    use std::cmp::Ordering;
    use std::convert::TryFrom;
    use std::fmt;
    use std::hash::Hasher;

    use thiserror::Error;

    /// A BLS12-381 public key as bytes.
    #[derive(Copy, Clone)]
    pub struct PublicKeyBytes(pub [u8; PublicKeyBytes::SIZE]);
    crate::derive_serde!(PublicKeyBytes, PublicKeyBytes::SIZE);

    impl PublicKeyBytes {
        pub const SIZE: usize = 96;

        #[inline]
        pub fn as_bytes(&self) -> &[u8; PublicKeyBytes::SIZE] {
            &self.0
        }
    }

    /// These conversions are used for the CLI only
    mod conversions_for_cli {
        use super::*;

        impl From<PublicKeyBytes> for String {
            fn from(bytes: PublicKeyBytes) -> String {
                base64::encode(&bytes.0[..])
            }
        }

        impl TryFrom<&str> for PublicKeyBytes {
            type Error = ThresholdSigPublicKeyBytesConversionError;

            fn try_from(string: &str) -> Result<Self, Self::Error> {
                let bytes = base64::decode(string).map_err(|e| {
                    ThresholdSigPublicKeyBytesConversionError::Malformed {
                        key_bytes: Some(string.as_bytes().to_vec()),
                        internal_error: format!(
                            "public key is not a valid base64 encoded string: {}",
                            e
                        ),
                    }
                })?;
                if bytes.len() != PublicKeyBytes::SIZE {
                    return Err(ThresholdSigPublicKeyBytesConversionError::Malformed {
                        key_bytes: Some(string.as_bytes().to_vec()),
                        internal_error: "public key length is incorrect".to_string(),
                    });
                }
                let mut buffer = [0u8; PublicKeyBytes::SIZE];
                buffer.copy_from_slice(&bytes);
                Ok(PublicKeyBytes(buffer))
            }
        }

        impl TryFrom<&String> for PublicKeyBytes {
            type Error = ThresholdSigPublicKeyBytesConversionError;

            fn try_from(string: &String) -> Result<Self, Self::Error> {
                PublicKeyBytes::try_from(string.as_str())
            }
        }
    }

    /// Converting a threshold signature public key to bytes failed.
    #[derive(Clone, Debug, PartialEq, Eq, Hash, Error)]
    pub enum ThresholdSigPublicKeyBytesConversionError {
        #[error("malformed threshold signature public key: {internal_error}")]
        Malformed {
            key_bytes: Option<Vec<u8>>,
            internal_error: String,
        },
    }

    impl fmt::Debug for PublicKeyBytes {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "0x{}", hex::encode(&self.0[..]))
        }
    }

    impl PartialEq for PublicKeyBytes {
        fn eq(&self, other: &Self) -> bool {
            self.0[..] == other.0[..]
        }
    }

    impl Eq for PublicKeyBytes {}

    impl Ord for PublicKeyBytes {
        fn cmp(&self, other: &Self) -> Ordering {
            self.0.cmp(&other.0)
        }
    }

    impl PartialOrd for PublicKeyBytes {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    impl Hash for PublicKeyBytes {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.0[..].hash(state);
        }
    }
}
