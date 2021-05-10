//! This file contains utilities for conversions to and from external or generic
//! types.
//!
//! These methods SHOULD not not be used within the CSP.
//!
//! Generic types such as those that appear here MUST not be used in the CSP
//! API.

use super::{CspSignature, MultiBls12_381_Signature, SigConverter, ThresBls12_381_Signature};
use ic_crypto_internal_basic_sig_ecdsa_secp256k1::types as secp256k1_types;
use ic_crypto_internal_basic_sig_ecdsa_secp256r1::types as ecdsa_types;
use ic_crypto_internal_basic_sig_ed25519::types as ed25519_types;
use ic_crypto_internal_multi_sig_bls12381::types as multi_types;
use ic_crypto_internal_threshold_sig_bls12381::types as threshold_types;
use ic_types::crypto::{
    AlgorithmId, BasicSigOf, CombinedMultiSigOf, CombinedThresholdSig, CombinedThresholdSigOf,
    CryptoError, CryptoResult, IndividualMultiSigOf, ThresholdSigShare, ThresholdSigShareOf,
};

use std::convert::TryFrom;

#[cfg(test)]
mod tests;

// TODO (CRP-201): Remove generic methods in CSP conversions
impl<T> TryFrom<&IndividualMultiSigOf<T>> for CspSignature {
    type Error = CryptoError;

    fn try_from(sig: &IndividualMultiSigOf<T>) -> Result<Self, Self::Error> {
        const SIG_LEN: usize = multi_types::IndividualSignatureBytes::SIZE;
        let sig_bytes = &sig.get_ref().0;

        if sig_bytes.len() != SIG_LEN {
            return Err(CryptoError::MalformedSignature {
                algorithm: AlgorithmId::MultiBls12_381,
                sig_bytes: sig_bytes.to_vec(),
                internal_error: format!(
                    "Expected multi-signature with {} bytes but got {} bytes",
                    SIG_LEN,
                    sig_bytes.len()
                ),
            });
        }
        let mut bytes: [u8; SIG_LEN] = [0; SIG_LEN];
        bytes.copy_from_slice(&sig_bytes[0..SIG_LEN]);
        Ok(CspSignature::MultiBls12_381(
            MultiBls12_381_Signature::Individual(multi_types::IndividualSignatureBytes(bytes)),
        ))
    }
}

// TODO (CRP-201): Remove generic methods in CSP conversions
impl<T> TryFrom<&CombinedMultiSigOf<T>> for CspSignature {
    type Error = CryptoError;

    fn try_from(sig: &CombinedMultiSigOf<T>) -> Result<Self, Self::Error> {
        const SIG_LEN: usize = multi_types::CombinedSignatureBytes::SIZE;
        let sig_bytes = &sig.get_ref().0;

        if sig_bytes.len() != SIG_LEN {
            return Err(CryptoError::MalformedSignature {
                algorithm: AlgorithmId::MultiBls12_381,
                sig_bytes: sig_bytes.to_vec(),
                internal_error: format!(
                    "Expected multi signature with {} bytes but got {} bytes",
                    SIG_LEN,
                    sig_bytes.len()
                ),
            });
        }
        let mut bytes: [u8; SIG_LEN] = [0; SIG_LEN];
        bytes.copy_from_slice(&sig_bytes[0..SIG_LEN]);
        Ok(CspSignature::MultiBls12_381(
            MultiBls12_381_Signature::Combined(multi_types::CombinedSignatureBytes(bytes)),
        ))
    }
}

// TODO (CRP-201): Remove generic methods in CSP conversions
impl<T> TryFrom<&ThresholdSigShareOf<T>> for CspSignature {
    type Error = CryptoError;

    fn try_from(sig: &ThresholdSigShareOf<T>) -> Result<Self, Self::Error> {
        const SIG_LEN: usize = threshold_types::IndividualSignatureBytes::SIZE;
        let sig_bytes = &sig.get_ref().0;

        if sig_bytes.len() != SIG_LEN {
            return Err(CryptoError::MalformedSignature {
                algorithm: AlgorithmId::ThresBls12_381,
                sig_bytes: sig_bytes.to_vec(),
                internal_error: format!(
                    "Expected threshold signature with {} bytes but got {} bytes",
                    SIG_LEN,
                    sig_bytes.len()
                ),
            });
        }
        let mut bytes: [u8; SIG_LEN] = [0; SIG_LEN];
        bytes.copy_from_slice(&sig_bytes[0..SIG_LEN]);
        Ok(CspSignature::ThresBls12_381(
            ThresBls12_381_Signature::Individual(threshold_types::IndividualSignatureBytes(bytes)),
        ))
    }
}

// TODO (CRP-201): Remove generic methods in CSP conversions
impl<T> TryFrom<&CombinedThresholdSigOf<T>> for CspSignature {
    type Error = CryptoError;

    fn try_from(sig: &CombinedThresholdSigOf<T>) -> Result<Self, Self::Error> {
        const SIG_LEN: usize = threshold_types::CombinedSignatureBytes::SIZE;
        let sig_bytes = &sig.get_ref().0;

        if sig_bytes.len() != SIG_LEN {
            return Err(CryptoError::MalformedSignature {
                algorithm: AlgorithmId::ThresBls12_381,
                sig_bytes: sig_bytes.to_vec(),
                internal_error: format!(
                    "Expected threshold signature with {} bytes but got {} bytes",
                    SIG_LEN,
                    sig_bytes.len()
                ),
            });
        }
        let mut bytes: [u8; SIG_LEN] = [0; SIG_LEN];
        bytes.copy_from_slice(&sig_bytes[0..SIG_LEN]);
        Ok(CspSignature::ThresBls12_381(
            ThresBls12_381_Signature::Combined(threshold_types::CombinedSignatureBytes(bytes)),
        ))
    }
}

// TODO (DFN-1186): Implement From instead of TryFrom once types are simplified
impl<T> TryFrom<CspSignature> for ThresholdSigShareOf<T> {
    type Error = CryptoError;

    fn try_from(csp_signature: CspSignature) -> Result<Self, Self::Error> {
        threshold_types::IndividualSignatureBytes::try_from(csp_signature)
            .map(|bytes| ThresholdSigShareOf::new(ThresholdSigShare(bytes.0.to_vec())))
    }
}

// TODO (DFN-1186): Implement From instead of TryFrom once types are simplified
impl<T> TryFrom<CspSignature> for CombinedThresholdSigOf<T> {
    type Error = CryptoError;

    fn try_from(csp_signature: CspSignature) -> Result<Self, Self::Error> {
        threshold_types::CombinedSignatureBytes::try_from(csp_signature)
            .map(|bytes| CombinedThresholdSigOf::new(CombinedThresholdSig(bytes.0.to_vec())))
    }
}

impl SigConverter {
    /// Convert from a BasicSigOf to a CspSignature
    pub fn try_from_basic<T>(&self, signature: &BasicSigOf<T>) -> CryptoResult<CspSignature> {
        match self.target_algorithm {
            AlgorithmId::Ed25519 => {
                const SIG_LEN: usize = ed25519_types::SignatureBytes::SIZE;
                let sig_bytes = &signature.get_ref().0;

                if sig_bytes.len() != SIG_LEN {
                    return Err(CryptoError::MalformedSignature {
                        algorithm: AlgorithmId::Ed25519,
                        sig_bytes: sig_bytes.to_vec(),
                        internal_error: format!(
                            "Invalid length: Expected Ed25519 signature with {} bytes but got {} bytes",
                            SIG_LEN,
                            sig_bytes.len()
                        ),
                    });
                }
                let mut bytes: [u8; SIG_LEN] = [0; SIG_LEN];
                bytes.copy_from_slice(&sig_bytes[0..SIG_LEN]);
                Ok(CspSignature::Ed25519(ed25519_types::SignatureBytes(bytes)))
            }
            AlgorithmId::EcdsaP256 => {
                const SIG_LEN: usize = ecdsa_types::SignatureBytes::SIZE;
                let sig_bytes = &signature.get_ref().0;

                if sig_bytes.len() != SIG_LEN {
                    return Err(CryptoError::MalformedSignature {
                        algorithm: AlgorithmId::EcdsaP256,
                        sig_bytes: sig_bytes.to_vec(),
                        internal_error: format!(
                            "Invalid length: Expected ECDSA-P256 signature with {} bytes but got {} bytes",
                            SIG_LEN,
                            sig_bytes.len()
                        ),
                    });
                }
                let mut bytes: [u8; SIG_LEN] = [0; SIG_LEN];
                bytes.copy_from_slice(&sig_bytes[0..SIG_LEN]);
                Ok(CspSignature::EcdsaP256(ecdsa_types::SignatureBytes(bytes)))
            }
            AlgorithmId::EcdsaSecp256k1 => {
                const SIG_LEN: usize = ecdsa_types::SignatureBytes::SIZE;
                let sig_bytes = &signature.get_ref().0;

                if sig_bytes.len() != SIG_LEN {
                    return Err(CryptoError::MalformedSignature {
                        algorithm: AlgorithmId::EcdsaSecp256k1,
                        sig_bytes: sig_bytes.to_vec(),
                        internal_error: format!(
                            "Invalid length: Expected ECDSA-SECP256k1 signature with {} bytes but got {} bytes",
                            SIG_LEN,
                            sig_bytes.len()
                        ),
                    });
                }
                let mut bytes: [u8; SIG_LEN] = [0; SIG_LEN];
                bytes.copy_from_slice(&sig_bytes[0..SIG_LEN]);
                Ok(CspSignature::EcdsaSecp256k1(
                    secp256k1_types::SignatureBytes(bytes),
                ))
            }
            algorithm => Err(CryptoError::AlgorithmNotSupported {
                algorithm,
                reason: "Expecting Ed25519 or ECDSA-P256 signature".to_string(),
            }),
        }
    }
}
