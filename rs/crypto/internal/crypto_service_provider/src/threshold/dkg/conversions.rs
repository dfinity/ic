//! Specialisation of CSP types to CLib types by algorithm
//!
//! The CSP types in question are enums, potentially supporting may different
//! variants.  Each of these methods takes such a CSP enum instance and checks
//! whether it is a specific desired variant.  If it is, it returns the specific
//! type.  If not, it returns an error.
use crate::types::{
    CspDealing, CspDkgTranscript, CspEncryptedSecretKey, CspPop, CspPublicCoefficients, CspResponse,
};
use dkg::types::{
    CLibDealingBytes, CLibResponseBytes, CLibTranscriptBytes, EncryptedShareBytes,
    EphemeralPopBytes, EphemeralPublicKeyBytes,
};
use ic_crypto_internal_threshold_sig_bls12381::api::dkg_errors;
use ic_crypto_internal_threshold_sig_bls12381::dkg::secp256k1 as dkg;
use ic_crypto_internal_types::sign::threshold_sig::dkg::encryption_public_key::{
    CspEncryptionPublicKey, InternalCspEncryptionPublicKey,
};
use ic_types::crypto::AlgorithmId;
use std::collections::BTreeMap;

#[allow(irrefutable_let_patterns)] // There is currently only one version of DKG.
pub fn public_key(
    public_key: CspEncryptionPublicKey,
) -> Result<EphemeralPublicKeyBytes, dkg_errors::MalformedPublicKeyError> {
    if let InternalCspEncryptionPublicKey::Secp256k1(variant) = public_key.internal {
        Ok(variant)
    } else {
        Err(dkg_errors::MalformedPublicKeyError {
            algorithm: AlgorithmId::Secp256k1,
            internal_error: format!("Incorrect public key type: {:?}", public_key),
            key_bytes: None,
        })
    }
}

pub fn pop(pop: CspPop) -> Result<EphemeralPopBytes, dkg_errors::MalformedPopError> {
    if let CspPop::Secp256k1(variant) = pop {
        Ok(variant)
    } else {
        Err(dkg_errors::MalformedPopError {
            algorithm: AlgorithmId::Secp256k1,
            internal_error: format!("Incorrect pop type: {:?}", pop),
            bytes: None,
        })
    }
}

pub fn public_key_with_pop(
    tuple: (CspEncryptionPublicKey, CspPop),
) -> Result<(EphemeralPublicKeyBytes, EphemeralPopBytes), dkg_errors::MalformedPublicKeyError> {
    if let (
        CspEncryptionPublicKey {
            internal: InternalCspEncryptionPublicKey::Secp256k1(public_key),
        },
        CspPop::Secp256k1(pop),
    ) = tuple
    {
        Ok((public_key, pop))
    } else {
        Err(dkg_errors::MalformedPublicKeyError {
            algorithm: AlgorithmId::Secp256k1,
            internal_error: format!("Incorrect type: {:?}", tuple),
            key_bytes: None,
        })
    }
}

pub fn receiver_keys(
    receiver_keys: &[Option<(CspEncryptionPublicKey, CspPop)>],
) -> Result<
    Vec<Option<(EphemeralPublicKeyBytes, EphemeralPopBytes)>>,
    dkg_errors::MalformedPublicKeyError,
> {
    receiver_keys
        .iter()
        .map(|keys_maybe| keys_maybe.map(public_key_with_pop).transpose())
        .collect()
}

#[allow(irrefutable_let_patterns)] // There is currently only one version of DKG.
pub fn encrypted_share(
    csp_key: CspEncryptedSecretKey,
) -> Result<EncryptedShareBytes, dkg_errors::MalformedDataError> {
    if let CspEncryptedSecretKey::ThresBls12_381(key) = csp_key {
        Ok(key)
    } else {
        Err(dkg_errors::MalformedDataError {
            algorithm: AlgorithmId::ThresBls12_381,
            internal_error: format!("Incorrect type: {:?}", csp_key),
            data: None,
        })
    }
}

#[allow(irrefutable_let_patterns)] // There is currently only one version of DKG.
pub fn dealing(
    csp_dealing: &CspDealing,
) -> Result<CLibDealingBytes, dkg_errors::MalformedDataError> {
    if let CspDealing {
        common_data: CspPublicCoefficients::Bls12_381(public_coefficients),
        receiver_data,
    } = csp_dealing
    {
        let receiver_data: Result<Vec<Option<EncryptedShareBytes>>, _> = receiver_data
            .iter()
            .map(|keys_maybe| keys_maybe.map(encrypted_share).transpose())
            .collect();
        Ok(CLibDealingBytes {
            public_coefficients: public_coefficients.clone(),
            receiver_data: receiver_data?,
        })
    } else {
        Err(dkg_errors::MalformedDataError {
            algorithm: AlgorithmId::Secp256k1,
            internal_error: format!("Incorrect type: {:?}", csp_dealing),
            data: None,
        })
    }
}

pub enum DealingMapConversionError {
    MalformedPublicKeyError(dkg_errors::MalformedPublicKeyError),
    MalformedDealingError(dkg_errors::MalformedDataError),
}
pub fn dealing_map(
    csp_dealings: &[((CspEncryptionPublicKey, CspPop), CspDealing)],
) -> Result<BTreeMap<EphemeralPublicKeyBytes, CLibDealingBytes>, DealingMapConversionError> {
    csp_dealings
        .iter()
        .map(|((csp_public_key, _pop), csp_dealing)| {
            let clib_public_key = self::public_key(*csp_public_key)
                .map_err(DealingMapConversionError::MalformedPublicKeyError)?;
            let clib_dealing =
                dealing(csp_dealing).map_err(DealingMapConversionError::MalformedDealingError)?;
            Ok((clib_public_key, clib_dealing))
        })
        .collect()
}

#[allow(irrefutable_let_patterns)] // There is currently only one version of DKG.
pub fn response(
    csp_response: CspResponse,
) -> Result<CLibResponseBytes, dkg_errors::MalformedDataError> {
    if let CspResponse::Secp256k1(response) = csp_response {
        Ok(response)
    } else {
        Err(dkg_errors::MalformedDataError {
            algorithm: AlgorithmId::Secp256k1,
            internal_error: format!("Incorrect type: {:?}", csp_response),
            data: None,
        })
    }
}

#[allow(irrefutable_let_patterns)] // There is currently only one version of DKG.
pub fn transcript(
    csp_transcript: CspDkgTranscript,
) -> Result<CLibTranscriptBytes, dkg_errors::MalformedDataError> {
    if let CspDkgTranscript::Secp256k1(transcript) = csp_transcript {
        Ok(transcript)
    } else {
        Err(dkg_errors::MalformedDataError {
            algorithm: AlgorithmId::Secp256k1,
            internal_error: format!("Incorrect type: {:?}", csp_transcript),
            data: None,
        })
    }
}

pub fn transcript_public_coefficients(csp_transcript: &CspDkgTranscript) -> CspPublicCoefficients {
    match csp_transcript {
        CspDkgTranscript::Secp256k1(clib_transcript) => {
            CspPublicCoefficients::Bls12_381(clib_transcript.public_coefficients.clone())
        }
    }
}
