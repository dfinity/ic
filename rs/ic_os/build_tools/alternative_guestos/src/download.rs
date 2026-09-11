use alternative_guestos::proposal::read_and_verify_signed_bless_alternative_guest_os_version_proposal;
use anyhow::{Context, Result};
use candid::{Encode, Principal};
use ic_agent::Agent;
use ic_certification::Certificate;
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use std::fs;
use std::path::Path;

pub async fn download_signed_proposal(
    proposal_id: u64,
    nns_url: &str,
    output: &Path,
) -> Result<()> {
    let governance_canister_id = Principal::from(GOVERNANCE_CANISTER_ID);
    let agent = Agent::builder()
        .with_url(nns_url)
        .build()
        .context("Failed to build NNS agent")?;
    let args = Encode!(&proposal_id).context("Failed to encode proposal id")?;
    let (_reply, certificate): (Vec<u8>, Certificate) = agent
        .update(&governance_canister_id, "get_proposal_info")
        .with_arg(args)
        .call()
        .and_wait()
        .await
        .context("Failed to download certified get_proposal_info response")?;

    fs::write(
        output,
        serde_cbor::to_vec(&certificate).context("Failed to serialize certificate as CBOR")?,
    )
    .with_context(|| {
        format!(
            "Failed to write proposal certificate to {}",
            output.display()
        )
    })?;

    read_and_verify_signed_bless_alternative_guest_os_version_proposal(output, None).with_context(
        || {
            format!(
                "Downloaded proposal at {} failed verification",
                output.display()
            )
        },
    )?;

    Ok(())
}
