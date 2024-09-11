use candid::Principal;
use ic_cdk::api::call::call;
use std::sync::atomic::{AtomicU64, Ordering};

const REGISTRY_CANISTER_ID: &str = "rwlgt-iiaaa-aaaaa-aaaaa-cai";
const REGISTRY_CANISTER_METHOD: &str = "get_api_boundary_node_ids";

static API_BNS_COUNT: AtomicU64 = AtomicU64::new(0);

#[ic_cdk::query]
fn get_api_boundary_nodes_count() -> u64 {
    API_BNS_COUNT.load(Ordering::Relaxed)
}

#[derive(candid::CandidType, candid::Deserialize)]
pub struct GetApiBoundaryNodeIdsRequest {}

#[ic_cdk::init]
fn init(timer_interval_secs: u64) {
    let interval = std::time::Duration::from_secs(timer_interval_secs);
    ic_cdk_timers::set_timer_interval(interval, || {
        ic_cdk::spawn(async {
            let canister_id = Principal::from_text(REGISTRY_CANISTER_ID).unwrap();
            let (result,): (Result<Vec<Option<Principal>>, String>,) = call(
                canister_id,
                REGISTRY_CANISTER_METHOD,
                (&GetApiBoundaryNodeIdsRequest {},),
            )
            .await
            .unwrap();
            let api_bns_count = result.unwrap().len();
            API_BNS_COUNT.store(api_bns_count as u64, Ordering::Relaxed);
        });
    });
}

#[ic_cdk::post_upgrade]
fn post_upgrade(timer_interval_secs: u64) {
    init(timer_interval_secs)
}
