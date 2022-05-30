use ic_certified_vars::verify_certificate;
use ic_types::{crypto::threshold_sig::ThresholdSigPublicKey, CanisterId};
use ledger_canister::{EncodedBlock, HashOf};

pub(crate) fn verify_block_hash(
    cert: &ledger_canister::Certification,
    hash: HashOf<EncodedBlock>,
    root_key: &Option<ThresholdSigPublicKey>,
    canister_id: &CanisterId,
) -> Result<(), String> {
    match root_key {
        Some(root_key) => {
            verify_certificate(
                cert.as_ref()
                    .ok_or("verify tip failed: no data certificate present")?,
                canister_id,
                root_key,
                &hash.into_bytes(),
            )
            .map_err(|e| format!("Certification error: {:?}", e))?;
            Ok(())
        }
        None => Ok(()),
    }
}
