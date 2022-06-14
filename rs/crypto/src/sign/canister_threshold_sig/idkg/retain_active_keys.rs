use ic_crypto_internal_csp::api::CspIDkgProtocol;
use ic_crypto_internal_threshold_sig_ecdsa::IDkgTranscriptInternal;
use ic_types::crypto::canister_threshold_sig::error::IDkgRetainThresholdKeysError;
use ic_types::crypto::canister_threshold_sig::idkg::IDkgTranscript;
use std::collections::BTreeSet;
use std::convert::TryFrom;

pub fn retain_active_transcripts<C: CspIDkgProtocol>(
    csp_client: &C,
    active_transcripts: &BTreeSet<IDkgTranscript>,
) -> Result<(), IDkgRetainThresholdKeysError> {
    let internal_transcripts: Result<BTreeSet<_>, _> = active_transcripts
        .iter()
        .map(|transcript| {
            IDkgTranscriptInternal::try_from(transcript).map_err(|e| {
                IDkgRetainThresholdKeysError::SerializationError {
                    internal_error: format!("failed to deserialize internal transcript: {:?}", e),
                }
            })
        })
        .collect();
    csp_client.idkg_retain_threshold_keys_if_present(&internal_transcripts?)
}
