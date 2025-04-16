use ic_crypto_internal_types::sign::threshold_sig::ni_dkg::CspNiDkgTranscript;
use ic_crypto_internal_types::sign::threshold_sig::public_key::bls12_381::{
    CspNiDkgTranscriptThresholdSigPublicKeyBytesConversionError, PublicKeyBytes,
};
use ic_protobuf::registry::subnet::v1::InitialNiDkgTranscriptRecord;
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;

#[derive(Eq, PartialEq, Debug)]
pub enum SubnetPubKeyExtractionError {
    CoefficientsEmpty,
    Deserialization,
}

#[derive(Eq, PartialEq, Debug)]
pub enum ThresholdPubKeyExtractionError {
    CoefficientsEmpty,
}

/// Extract the subnet threshold signing public key from an [`InitialNiDkgTranscriptRecord`].
///
/// # Errors
/// * [`SubnetPubKeyExtractionError::CoefficientsEmpty`] if the `Groth20_Bls12_381` coefficients
///   are empty
/// * [`SubnetPubKeyExtractionError::Deserialization`] if the `CspNiDkgTranscript` could not be
///   deserialized from the [`InitialNiDkgTranscriptRecord`] passed as input
pub fn extract_subnet_threshold_sig_public_key(
    initial_ni_dkg_transcript_record: &InitialNiDkgTranscriptRecord,
) -> Result<ThresholdSigPublicKey, SubnetPubKeyExtractionError> {
    let csp_ni_dkg_transcript = CspNiDkgTranscript::try_from(initial_ni_dkg_transcript_record)
        .map_err(|_| SubnetPubKeyExtractionError::Deserialization)?;
    extract_threshold_sig_public_key(&csp_ni_dkg_transcript).map_err(|err| match err {
        ThresholdPubKeyExtractionError::CoefficientsEmpty => {
            SubnetPubKeyExtractionError::CoefficientsEmpty
        }
    })
}

/// Extract the threshold signature public key from a [`CspNiDkgTranscript`].
///
/// # Errors
/// * [`ThresholdPubKeyExtractionError::CoefficientsEmpty`] if the `Groth20_Bls12_381` coefficients
///   are empty
pub fn extract_threshold_sig_public_key(
    csp_ni_dkg_transcript: &CspNiDkgTranscript,
) -> Result<ThresholdSigPublicKey, ThresholdPubKeyExtractionError> {
    let public_key_bytes = match PublicKeyBytes::try_from(csp_ni_dkg_transcript) {
        Ok(public_key_bytes) => public_key_bytes,
        Err(err) => match err {
            CspNiDkgTranscriptThresholdSigPublicKeyBytesConversionError::CoefficientsEmpty => {
                Err(ThresholdPubKeyExtractionError::CoefficientsEmpty)?
            }
        },
    };
    Ok(ThresholdSigPublicKey::from(public_key_bytes))
}
