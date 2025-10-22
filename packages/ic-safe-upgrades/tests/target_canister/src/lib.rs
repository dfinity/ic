use ic_cdk::management_canister::{CanisterInfoArgs, ChangeDetails, canister_info};
use ic_cdk::update;

#[update]
fn version() -> u32 {
    #[cfg(feature = "v1")]
    #[allow(unused_variables)]
    let v = 1;
    #[cfg(feature = "v2")]
    let v = 2;
    v
}

#[update]
async fn self_history() -> Vec<Vec<u8>> {
    let args = CanisterInfoArgs {
        canister_id: ic_cdk::api::canister_self(),
        num_requested_changes: Some(20),
    };
    let info = canister_info(&args)
        .await
        .expect("Failed to get canister info");
    info.recent_changes
        .iter()
        .filter_map(|change| match &change.details {
            ChangeDetails::CodeDeployment(deployment) => Some(deployment.module_hash.clone()),
            _ => None,
        })
        .collect()
}

fn main() {}
