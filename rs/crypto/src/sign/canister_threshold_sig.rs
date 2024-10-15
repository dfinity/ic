use ic_crypto_internal_threshold_sig_ecdsa::IDkgTranscriptInternal;
use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscript;
use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscriptType::{Masked, Unmasked};
use ic_types::crypto::canister_threshold_sig::MasterPublicKey;

pub mod ecdsa;
mod idkg;
pub mod schnorr;
#[cfg(test)]
pub(crate) mod test_utils;
#[cfg(test)]
mod tests;

pub use idkg::{retrieve_mega_public_key_from_registry, MegaKeyFromRegistryError};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub enum MasterPublicKeyExtractionError {
    UnsupportedAlgorithm(String),
    SerializationError(String),
    CannotExtractFromMasked,
}

/// Extracts the master public key from the given `idkg_transcript`.
pub fn get_master_public_key_from_transcript(
    idkg_transcript: &IDkgTranscript,
) -> Result<MasterPublicKey, MasterPublicKeyExtractionError> {
    if idkg_transcript.algorithm_id.is_threshold_ecdsa() {
        match idkg_transcript.transcript_type {
            Unmasked(_) => {
                let internal_transcript = IDkgTranscriptInternal::try_from(idkg_transcript)
                    .map_err(|e| {
                        MasterPublicKeyExtractionError::SerializationError(format!("{:?}", e))
                    })?;
                ecdsa::get_tecdsa_master_public_key_from_internal_transcript(&internal_transcript)
            }
            Masked(_) => Err(MasterPublicKeyExtractionError::CannotExtractFromMasked),
        }
    } else if idkg_transcript.algorithm_id.is_threshold_schnorr() {
        match idkg_transcript.transcript_type {
            Unmasked(_) => {
                let internal_transcript = IDkgTranscriptInternal::try_from(idkg_transcript)
                    .map_err(|e| {
                        MasterPublicKeyExtractionError::SerializationError(format!("{:?}", e))
                    })?;
                schnorr::get_tschnorr_master_public_key_from_internal_transcript(
                    &internal_transcript,
                )
            }
            Masked(_) => Err(MasterPublicKeyExtractionError::CannotExtractFromMasked),
        }
    } else {
        Err(MasterPublicKeyExtractionError::UnsupportedAlgorithm(
            format!("{:?}", idkg_transcript.algorithm_id),
        ))
    }
}
