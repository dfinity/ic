//! Smoke test for an API boundary node, e.g. the disaster-recovery one built
//! from `ic-os/api-bn-recovery`.
//!
//! Through the given boundary node, it checks that `/api/v2/status` serves the
//! IC mainnet root key and makes an anonymous query of `name` on the ICP
//! ledger. The node signatures on the reply are checked against node keys from
//! a certified `read_state`, which is verified with the IC mainnet root key
//! built into `ic-agent`, so a boundary node that forges or alters the reply
//! fails the test.

use anyhow::{Context, Result, bail, ensure};
use candid::{CandidType, Decode, Deserialize, Encode, Principal};
use clap::Parser;
use ic_agent::Agent;
use std::time::Duration;
use url::Url;

const LEDGER_CANISTER_ID: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
const EXPECTED_NAME: &str = "Internet Computer";
const TIMEOUT: Duration = Duration::from_secs(60);

/// Queries the ICP ledger through an API boundary node and verifies the reply
/// against the IC mainnet root key (mainnet only).
#[derive(Parser)]
struct Cli {
    /// URL of the API boundary node, e.g. http://localhost:8080
    #[arg(long)]
    url: Url,
}

/// Reply of `name : () -> (record { name : text }) query` (rs/ledger_suite/icp/ledger.did).
#[derive(CandidType, Deserialize)]
struct NameResponse {
    name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Keep ic-agent's defaults: the anonymous identity, the IC mainnet root key
    // built into ic-agent and verified query signatures. Never call
    // fetch_root_key(), which would trust whatever key the boundary node under
    // test serves, and never enable background dynamic routing, which would send
    // the requests to other boundary nodes.
    let agent = Agent::builder()
        .with_url(cli.url.as_str())
        .build()
        .context("failed to build the agent")?;
    let mainnet_root_key = agent.read_root_key();
    let ledger = Principal::from_text(LEDGER_CANISTER_ID)?;
    let arg = Encode!()?;

    let check = async {
        // Clients pointed at a custom URL (e.g. `dfx --network <url>`) fetch the
        // root key from /api/v2/status and trust it, so it must be the mainnet one.
        let status = agent.status().await.context("GET /api/v2/status failed")?;
        match status.root_key {
            Some(root_key) if root_key == mainnet_root_key => {}
            Some(_) => bail!("/api/v2/status serves a root key other than the IC mainnet one"),
            None => bail!("/api/v2/status serves no root key (registry not synced yet?)"),
        }
        agent
            .query(&ledger, "name")
            .with_arg(arg)
            .call_with_verification()
            .await
            .context("query of the ICP ledger's name failed")
    };
    let reply = tokio::time::timeout(TIMEOUT, check)
        .await
        .with_context(|| format!("did not complete within {TIMEOUT:?}"))??;

    let NameResponse { name } =
        Decode!(&reply, NameResponse).context("failed to decode the reply")?;
    ensure!(
        name == EXPECTED_NAME,
        "expected {EXPECTED_NAME:?}, got {name:?}"
    );
    println!(
        "{LEDGER_CANISTER_ID}.name() via {} returned {name:?}",
        cli.url
    );
    Ok(())
}
