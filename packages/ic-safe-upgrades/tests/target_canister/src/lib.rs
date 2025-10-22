use ic_cdk::management_canister::{CanisterInfoArgs, ChangeDetails, canister_info};
use ic_cdk::update;

// Clippy always evaluates with all features on so it complains that the code below is
// unreachable
#[allow(unreachable_code)]
#[update]
fn version() -> u32 {
    #[cfg(feature = "v1")]
    {
        return 1;
    }
    #[cfg(feature = "v2")]
    {
        return 2;
    }
    0
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
