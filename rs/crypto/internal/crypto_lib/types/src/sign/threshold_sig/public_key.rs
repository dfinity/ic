//! Data types for threshold public keys.
use crate::sign::threshold_sig::ni_dkg::CspNiDkgTranscript;
use crate::sign::threshold_sig::public_key::bls12_381::{
    CspNiDkgTranscriptThresholdSigPublicKeyBytesConversionError, PublicKeyBytes,
};
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use thiserror::Error;

/// A threshold signature public key.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Deserialize, Serialize)]
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

/// Converting an NI-DKG transcript to a BLS 12 381 CspThresholdSigPublicKey struct failed.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Error)]
pub enum CspNiDkgTranscriptToCspThresholdSigPublicKeyConversionError {
    #[error("the public coefficients of the threshold public key are empty")]
    CoefficientsEmpty,
}

impl From<CspNiDkgTranscriptThresholdSigPublicKeyBytesConversionError>
    for CspNiDkgTranscriptToCspThresholdSigPublicKeyConversionError
{
    fn from(err: CspNiDkgTranscriptThresholdSigPublicKeyBytesConversionError) -> Self {
        match err {
            CspNiDkgTranscriptThresholdSigPublicKeyBytesConversionError::CoefficientsEmpty => {
                CspNiDkgTranscriptToCspThresholdSigPublicKeyConversionError::CoefficientsEmpty
            }
        }
    }
}

impl TryFrom<&CspNiDkgTranscript> for CspThresholdSigPublicKey {
    type Error = CspNiDkgTranscriptToCspThresholdSigPublicKeyConversionError;

    fn try_from(csp_ni_dkg_transcript: &CspNiDkgTranscript) -> Result<Self, Self::Error> {
        let public_key_bytes = PublicKeyBytes::try_from(csp_ni_dkg_transcript)?;
        Ok(Self::ThresBls12_381(public_key_bytes))
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

    impl AsRef<[u8]> for PublicKeyBytes {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    /// Converting a threshold signature public key to bytes failed.
    #[derive(Clone, Eq, PartialEq, Hash, Debug, Error)]
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

    /// Converting an NI-DKG transcript to a BLS 12 381 public key bytes struct failed.
    #[derive(Clone, Eq, PartialEq, Hash, Debug, Error)]
    pub enum CspNiDkgTranscriptThresholdSigPublicKeyBytesConversionError {
        #[error("coefficients empty")]
        CoefficientsEmpty,
    }

    impl TryFrom<&CspNiDkgTranscript> for PublicKeyBytes {
        type Error = CspNiDkgTranscriptThresholdSigPublicKeyBytesConversionError;

        fn try_from(csp_ni_dkg_transcript: &CspNiDkgTranscript) -> Result<Self, Self::Error> {
            match csp_ni_dkg_transcript {
                CspNiDkgTranscript::Groth20_Bls12_381(transcript) => Ok(
                    transcript
                        .public_coefficients
                        .coefficients.first()
                        .copied()
                        .ok_or(
                            CspNiDkgTranscriptThresholdSigPublicKeyBytesConversionError::CoefficientsEmpty,
                        )?,
                ),
            }
        }
    }
}
