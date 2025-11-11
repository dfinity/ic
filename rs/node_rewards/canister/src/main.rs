use ic_cdk::api::in_replicated_execution;
use ic_cdk::{init, post_upgrade, pre_upgrade, query, update};
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_nervous_system_canisters::registry::RegistryCanister;
use ic_nervous_system_timer_task::{RecurringSyncTask, TimerTaskMetricsRegistry};
use ic_nns_constants::GOVERNANCE_CANISTER_ID;
use ic_node_rewards_canister::canister::NodeRewardsCanister;
use ic_node_rewards_canister::storage::{
    LAST_DAY_SYNCED, METRICS_MANAGER, RegistryStoreStableMemoryBorrower,
};
use ic_node_rewards_canister::telemetry::PROMETHEUS_METRICS;
use ic_node_rewards_canister::timer_tasks::{
    GetNodeProvidersRewardsInstructionsExporter, HourlySyncTask,
};
use ic_node_rewards_canister_api::monthly_rewards::{
    GetNodeProvidersMonthlyXdrRewardsRequest, GetNodeProvidersMonthlyXdrRewardsResponse,
};
use ic_node_rewards_canister_api::provider_rewards_calculation::{
    GetNodeProvidersRewardsCalculationRequest, GetNodeProvidersRewardsCalculationResponse,
};
use ic_node_rewards_canister_api::providers_rewards::{
    GetNodeProvidersRewardsRequest, GetNodeProvidersRewardsResponse,
};
use ic_registry_canister_client::StableCanisterRegistryClient;
use std::cell::RefCell;
use std::sync::Arc;

fn main() {}

thread_local! {
    static REGISTRY_STORE: Arc<StableCanisterRegistryClient<RegistryStoreStableMemoryBorrower>> = {
        let store = StableCanisterRegistryClient::<RegistryStoreStableMemoryBorrower>::new(
            Arc::new(RegistryCanister::new()));
        Arc::new(store)
    };
    static CANISTER: RefCell<NodeRewardsCanister> = {
        let registry_store = REGISTRY_STORE.with(|store| {
            store.clone()
        });
        let metrics_manager = METRICS_MANAGER.with(|m| m.clone());

        RefCell::new(NodeRewardsCanister::new(registry_store, metrics_manager, &LAST_DAY_SYNCED))
    };

    static METRICS_REGISTRY: RefCell<TimerTaskMetricsRegistry> = RefCell::new(TimerTaskMetricsRegistry::default());
}

#[init]
fn canister_init() {
    schedule_timers();
}

#[pre_upgrade]
fn pre_upgrade() {}

#[post_upgrade]
fn post_upgrade() {
    schedule_timers();
}

pub fn schedule_timers() {
    HourlySyncTask::new(&CANISTER).schedule(&METRICS_REGISTRY);
    GetNodeProvidersRewardsInstructionsExporter::new(&CANISTER).schedule(&METRICS_REGISTRY);
}

fn panic_if_caller_not_governance() {
    if ic_cdk::api::msg_caller() != GOVERNANCE_CANISTER_ID.get().0 {
        panic!("Only the governance canister can call this method");
    }
}

#[cfg(any(feature = "test", test))]
#[query(hidden = true)]
fn get_registry_value(key: String) -> Result<Option<Vec<u8>>, String> {
    CANISTER.with(|canister| canister.borrow().get_registry_value(key))
}

#[update]
async fn get_node_providers_monthly_xdr_rewards(
    request: GetNodeProvidersMonthlyXdrRewardsRequest,
) -> GetNodeProvidersMonthlyXdrRewardsResponse {
    panic_if_caller_not_governance();
    NodeRewardsCanister::get_node_providers_monthly_xdr_rewards(&CANISTER, request).await
}

#[update]
fn get_node_providers_rewards(
    request: GetNodeProvidersRewardsRequest,
) -> GetNodeProvidersRewardsResponse {
    panic_if_caller_not_governance();
    NodeRewardsCanister::get_node_providers_rewards(&CANISTER, request)
}

#[query]
fn get_node_providers_rewards_calculation(
    request: GetNodeProvidersRewardsCalculationRequest,
) -> GetNodeProvidersRewardsCalculationResponse {
    if in_replicated_execution() {
        return Err(
            "Replicated execution of this method is not allowed. Use a non-replicated query call."
                .to_string(),
        );
    }

    NodeRewardsCanister::get_node_providers_rewards_calculation(&CANISTER, request)
}

fn encode_metrics(w: &mut ic_metrics_encoder::MetricsEncoder<Vec<u8>>) -> std::io::Result<()> {
    METRICS_REGISTRY.with_borrow(|registry| registry.encode("node_rewards", w))?;
    PROMETHEUS_METRICS.with_borrow(|p| p.encode_metrics(w))
}

#[query(
    hidden = true,
    decode_with = "candid::decode_one_with_decoding_quota::<1000000,_>"
)]
fn http_request(request: HttpRequest) -> HttpResponse {
    match request.path() {
        "/metrics" => {
            let mut w = ic_metrics_encoder::MetricsEncoder::new(
                vec![],
                ic_cdk::api::time() as i64 / 1_000_000,
            );

            match encode_metrics(&mut w) {
                Ok(_) => HttpResponseBuilder::ok()
                    .header("Content-Type", "text/plain; version=0.0.4")
                    .header("Cache-Control", "no-store")
                    .with_body_and_content_length(w.into_inner())
                    .build(),
                Err(err) => {
                    HttpResponseBuilder::server_error(format!("Failed to encode metrics: {err}"))
                        .build()
                }
            }
        }
        _ => HttpResponseBuilder::not_found().build(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use candid_parser::utils::{CandidSource, service_equal};
    #[test]
    fn test_implemented_interface_matches_declared_interface_exactly() {
        let declared_interface = CandidSource::Text(include_str!("../node-rewards-canister.did"));

        // The line below generates did types and service definition from the
        // methods annotated with `candid_method` above. The definition is then
        // obtained with `__export_service()`.
        candid::export_service!();
        let implemented_interface_str = __export_service();
        let implemented_interface = CandidSource::Text(&implemented_interface_str);

        let result = service_equal(declared_interface, implemented_interface);
        assert!(result.is_ok(), "{:?}\n\n", result.unwrap_err());
    }
}
