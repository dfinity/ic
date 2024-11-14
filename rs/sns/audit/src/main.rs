use anyhow::bail;
use candid::Principal;
use ic_agent::Agent;
use ic_nervous_system_agent::sns::swap::SwapCanister;
use ic_sns_audit::validate_sns_swap;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        bail!("Please specify NNS_URL and SWAP_CANISTER_ID as CLI arguments.");
    }
    let nns_url = &args[1];
    let swap_canister_id = &args[2];
    let swap = SwapCanister::new(Principal::from_text(swap_canister_id).unwrap());

    let agent = Agent::builder()
        .with_url(nns_url)
        .with_verify_query_signatures(false)
        .build()?;

    validate_sns_swap(&agent, swap).await?;
    Ok(())
}
