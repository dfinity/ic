use anyhow::{Context, Result};
use ic_agent::Agent;
use ic_certification::{Certificate, LookupResult, SubtreeLookupResult};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::BlessAlternativeGuestOsVersion;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

/// Reads an alternative GuestOS proposal from disk and verifies that it's signed by the NNS public
/// key.
///
/// Returns `Ok(None)` if the proposal file doesn't exist, `Ok(Some(proposal))` if found
/// and fully verified, or `Err(_)` if verification fails.
pub fn read_and_verify_bless_alternative_guest_os_version_proposal(
    proposal_path: &Path,
    #[cfg(feature = "dev")] nns_public_key_override: Option<&[u8]>,
) -> Result<Option<BlessAlternativeGuestOsVersion>> {
    if !proposal_path.exists() {
        return Ok(None);
    }

    let proposal_bytes = fs::read(proposal_path)
        .with_context(|| format!("Failed to read proposal from {:?}", proposal_path))?;

    let certificate: Certificate = serde_cbor::from_slice(&proposal_bytes)
        .context("Failed to deserialize Certificate from CBOR")?;

    let agent = Agent::builder()
        // We need to provide some URL to make the builder happy
        .with_url("https://not_used")
        // We don't care about the certificate expiry (malicious host can fake time anyway)
        .with_ingress_expiry(Duration::from_secs(365_250_000 * 24 * 60 * 60))
        .build()
        .context("Failed to build agent")?;

    #[cfg(feature = "dev")]
    if let Some(nns_public_key) = nns_public_key_override {
        agent.set_root_key(nns_public_key.to_vec());
    }

    agent.verify(&certificate, GOVERNANCE_CANISTER_ID.into())?;

    let request_status = match certificate.tree.lookup_subtree(vec![b"request_status"]) {
        SubtreeLookupResult::Found(subtree) => subtree,
        _ => anyhow::bail!("request_status not found in certificate"),
    };

    let request_ids: HashSet<Vec<u8>> = request_status
        .list_paths()
        .into_iter()
        .filter_map(|path| path.first().map(|segment| segment.as_bytes().to_vec()))
        .collect();

    if request_ids.len() != 1 {
        anyhow::bail!(
            "Expected exactly one request ID, found {}",
            request_ids.len()
        );
    }

    let request_id = request_ids.into_iter().next().unwrap();

    let status = match request_status.lookup_path(vec![request_id.clone(), b"status".to_vec()]) {
        LookupResult::Found(bytes) => bytes,
        _ => anyhow::bail!("Status not found for request ID"),
    };

    if status != b"replied" {
        anyhow::bail!(
            "Request status is not 'replied': {}",
            String::from_utf8_lossy(status)
        );
    }

    let reply = match request_status.lookup_path(vec![request_id, b"reply".to_vec()]) {
        LookupResult::Found(bytes) => bytes,
        _ => anyhow::bail!("Reply not found for request ID"),
    };

    let (proposal,) = candid::decode_args::<(BlessAlternativeGuestOsVersion,)>(reply)
        .context("Failed to decode proposal from reply")?;

    Ok(Some(proposal))
}
