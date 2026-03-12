use anyhow::{Context, Error, Result, ensure};
use ic_certificate_verification::VerifyCertificate;
use ic_certification::{Certificate, LookupResult, SubtreeLookupResult};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_nns_governance_api::proposal::Action;
use ic_nns_governance_api::{BlessAlternativeGuestOsVersion, ProposalInfo, ProposalStatus};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

const NNS_PUBLIC_KEY: &[u8; 133] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";

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

    let nns_public_key = NNS_PUBLIC_KEY;
    // Allow overriding the NNS public key if running in dev or test mode
    #[cfg(any(feature = "dev", test))]
    let nns_public_key = nns_public_key_override.unwrap_or(nns_public_key);

    // Verify the certificate against the NNS public key. This is the proof that the proposal
    // came from the NNS governance canister.
    // All we want to know is whether the proposal passed at some point, because after that
    // point, it cannot "un-pass". Therefore, we don't care about the certificate's time.
    // Furthermore, we do not yet have a reliable source of time, and so, we wouldn't be able to
    // securely say, "this happened sufficiently recently".
    certificate.verify(
        GOVERNANCE_CANISTER_ID.get().as_slice(),
        nns_public_key,
        &0,
        &u128::MAX,
    )?;

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

    extract_action_from_proposal(&proposal_info)
        .with_context(|| format!("Invalid proposal_info: {proposal_info:?}"))
}

fn extract_action_from_proposal(
    proposal_info: &ProposalInfo,
) -> Result<BlessAlternativeGuestOsVersion, Error> {
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
        .as_ref()
        .context("ProposalInfo does not contain a proposal")?
        .action
        .as_ref()
        .context("Proposal does not contain an action")?;

    match proposal_action {
        Action::BlessAlternativeGuestOsVersion(p) => Ok(p.clone()),
        _ => anyhow::bail!("Proposal is not a BlessAlternativeGuestOsVersion"),
    }
}
