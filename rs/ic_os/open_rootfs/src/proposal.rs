use anyhow::{Context, Result, ensure};
use ic_agent::Agent;
use ic_certification::{Certificate, LookupResult, SubtreeLookupResult};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::proposal::Action;
use ic_nns_governance_api::{BlessAlternativeGuestOsVersion, ProposalInfo, ProposalStatus};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

/// Reads an alternative GuestOS proposal from disk and verifies that it's signed by the NNS public
/// key. Returns the parsed [`BlessAlternativeGuestOsVersion`] action from the proposal or an
/// error if the proposal is invalid or does not contain a [`BlessAlternativeGuestOsVersion`]
/// action.
///
/// The file pointed to by `proposal_path` must be acquired by:
/// 1. Passing and executing a [`BlessAlternativeGuestOsVersion`] proposal in the governance
///    canister.
/// 2. Making an update call to the governance canister's `get_proposal_info` method.
/// 3. Getting a CBOR-encoded [`Certificate`] for the update call
///    (e.g. by using ic-agent's Agent::update().call().and_wait()) and storing it in a file.
pub fn read_and_verify_signed_bless_alternative_guest_os_version_proposal(
    proposal_path: &Path,
    #[cfg(any(feature = "dev", test))] nns_public_key_override: Option<&[u8]>,
) -> Result<BlessAlternativeGuestOsVersion> {
    ensure!(
        proposal_path.exists(),
        "No alternative GuestOS proposal found at {}",
        proposal_path.display()
    );

    let proposal_bytes = fs::read(proposal_path)
        .with_context(|| format!("Failed to read proposal from {:?}", proposal_path))?;

    let certificate: Certificate = serde_cbor::from_slice(&proposal_bytes)
        .context("Failed to deserialize Certificate from CBOR")?;

    let agent = Agent::builder()
        // We need to provide some URL to make the builder happy
        .with_url("https://not_used")
        // All we want to know is whether the proposal passed at some point, because after that
        // point, it cannot "un-pass". Therefore, it is ok if we are looking an ancient
        // get_proposal_info response. Furthermore, we do not yet have a reliable source of time,
        // and so, we wouldn't be able to securely say, "this happened sufficiently recently".
        .with_ingress_expiry(Duration::from_secs(365_250_000 * 24 * 60 * 60))
        .build()
        .context("Failed to build agent")?;

    #[cfg(any(feature = "dev", test))]
    if let Some(nns_public_key) = nns_public_key_override {
        agent.set_root_key(nns_public_key.to_vec());
    }

    // Verify the certificate against the NNS public key. This is the proof that the proposal
    // came from the NNS governance canister.
    agent.verify(&certificate, GOVERNANCE_CANISTER_ID.into())?;

    let SubtreeLookupResult::Found(request_status) =
        certificate.tree.lookup_subtree(vec![b"request_status"])
    else {
        anyhow::bail!("request_status not found in certificate")
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

    let status = match request_status.lookup_path([&request_id[..], b"status"]) {
        LookupResult::Found(bytes) => bytes,
        _ => anyhow::bail!("Status not found for request ID"),
    };

    if status != b"replied" {
        anyhow::bail!(
            "Request status is not 'replied': {}",
            String::from_utf8_lossy(status)
        );
    }

    let reply = match request_status.lookup_path([&request_id[..], b"reply"]) {
        LookupResult::Found(bytes) => bytes,
        _ => anyhow::bail!("Reply not found for request ID"),
    };

    let (proposal_info,) = candid::decode_args::<(Option<ProposalInfo>,)>(reply)
        .context("Failed to decode ProposalInfo from reply")?;

    let proposal_info = proposal_info.context("ProposalInfo not found in reply")?;

    ensure!(
        proposal_info.status == ProposalStatus::Executed as i32,
        "Proposal status must be {}, but is {}",
        ProposalStatus::Executed.as_str_name(),
        ProposalStatus::from_repr(proposal_info.status)
            .map(|s| s.as_str_name().to_string())
            .unwrap_or_else(|| proposal_info.status.to_string())
    );

    let proposal_action = proposal_info
        .proposal
        .context("ProposalInfo does not contain a proposal")?
        .action
        .context("Proposal does not contain an action")?;

    match proposal_action {
        Action::BlessAlternativeGuestOsVersion(p) => Ok(p),
        _ => anyhow::bail!("Proposal is not a BlessAlternativeGuestOsVersion"),
    }
}
