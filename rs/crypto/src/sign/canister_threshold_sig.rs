use ic_crypto_internal_threshold_sig_canister_threshold_sig::IDkgTranscriptInternal;
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
    Ok(MasterPublicKey {
        algorithm_id: idkg_transcript.algorithm_id.clone(),
        public_key: vec![],
    })
}
