use ic_certification::verify_certified_data;
use ic_ledger_core::block::EncodedBlock;
use ic_ledger_hash_of::HashOf;
use ic_types::{CanisterId, crypto::threshold_sig::ThresholdSigPublicKey};

pub struct VerificationInfo {
    pub root_key: ThresholdSigPublicKey,
    pub canister_id: CanisterId,
}

pub(crate) fn verify_block_hash(
    cert: &icp_ledger::Certification,
    hash: HashOf<EncodedBlock>,
    info: &VerificationInfo,
) -> Result<(), String> {
    verify_certified_data(
        cert.as_ref()
            .ok_or("verify tip failed: no data certificate present")?,
        &info.canister_id,
        &info.root_key,
        &hash.into_bytes(),
    )
    .map(|_| ()) // we don't need the result so we discard it
    .map_err(|e| format!("Certification error: {e:?}"))
}
