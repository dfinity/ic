use candid::Principal;
use ic_sns_audit::validate_sns_swap;

#[tokio::main]
async fn main() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return Err("Please specify NNS_URL and SWAP_CANISTER_ID as CLI arguments.".to_string());
    }
    let nns_url = &args[1];
    let swap_canister_id = &args[2];
    let swap_canister_id = Principal::from_text(swap_canister_id).unwrap();
    validate_sns_swap(nns_url, swap_canister_id).await
}
