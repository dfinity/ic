use std::sync::atomic::{AtomicU64, Ordering};
use serde::{Deserialize, Serialize};
use candid::{Encode, Principal};
use ic_cdk::api::call::call;
use registry_canister::pb::v1::{ApiBoundaryNodeIdRecord, GetApiBoundaryNodeIdsRequest};

static COUNTER: AtomicU64 = AtomicU64::new(0);

#[ic_cdk::query]
fn counter() -> u64 {
    COUNTER.load(Ordering::Relaxed)
}

#[ic_cdk::init]
fn init(timer_interval_secs: u64) {
    let interval = std::time::Duration::from_secs(timer_interval_secs);
    ic_cdk::println!("Starting a periodic task with interval {interval:?}");
    ic_cdk_timers::set_timer_interval(interval, || {
        COUNTER.fetch_add(1, Ordering::Relaxed);
        ic_cdk::spawn(async {
            let canister_id = Principal::from_text("rwlgt-iiaaa-aaaaa-aaaaa-cai").unwrap();
            // let args = Encode!(&GetApiBoundaryNodeIdsRequest {}).unwrap();
            let (result,): (i64,) = call(canister_id, "get_api_boundary_node_ids", ())
                .await
                .unwrap();
        });
    });
}

#[ic_cdk::post_upgrade]
fn post_upgrade(timer_interval_secs: u64) {
    init(timer_interval_secs)
}