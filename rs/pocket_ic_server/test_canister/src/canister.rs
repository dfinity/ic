use ic_cdk::update;
use ic_management_canister_types::{NodeMetricsHistoryArgs, NodeMetricsHistoryResponse};

// management canister calls

#[update]
async fn node_metrics_history_proxy(
    args: NodeMetricsHistoryArgs,
) -> Vec<NodeMetricsHistoryResponse> {
    ic_cdk::api::call::call_with_payment128::<_, (Vec<NodeMetricsHistoryResponse>,)>(
        candid::Principal::management_canister(),
        "node_metrics_history",
        (args,),
        0_u128,
    )
    .await
    .unwrap()
    .0
}

fn main() {}
