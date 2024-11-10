use crate::access_control::{AccessLevelResolver, WithAuthorization};
use crate::add_config::{AddsConfig, ConfigAdder};
use crate::confidentiality_formatting::{
    ConfigConfidentialityFormatter, RuleConfidentialityFormatter,
};
use crate::disclose::{DisclosesRules, RulesDiscloser};
use crate::fetcher::{ConfigFetcher, EntityFetcher, RuleFetcher};
use crate::metrics::{
    export_metrics_as_http_response, with_metrics_registry, WithMetrics,
    LAST_CANISTER_UPGRADE_GAUGE, LAST_SUCCESSFUL_REGISTRY_POLL_GAUGE,
};
use crate::state::CanisterApi;
use crate::state::{init_version_and_config, with_canister_state};
use candid::Principal;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk::api::call::call;
use ic_cdk_macros::{init, post_upgrade, query, update};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use rate_limits_api::{
    AddConfigResponse, ApiBoundaryNodeIdRecord, DiscloseRulesArg, DiscloseRulesResponse,
    GetApiBoundaryNodeIdsRequest, GetConfigResponse, GetRuleByIdResponse, InitArg, InputConfig,
    RuleId, Version,
};
use std::sync::Arc;
use std::time::Duration;

const REGISTRY_CANISTER_METHOD: &str = "get_api_boundary_node_ids";

#[init]
fn init(init_arg: InitArg) {
    // TODO: rework logging
    ic_cdk::println!("Starting canister init");
    // Set authorized principal, which performs write operations, such as adding new configurations
    with_canister_state(|state| {
        if let Some(principal) = init_arg.authorized_principal {
            state.set_authorized_principal(principal);
        }
        if state.get_version().is_none() {
            ic_cdk::println!("Initializing rate-limit config");
            let current_time = ic_cdk::api::time();
            init_version_and_config(current_time, state.clone());
        } else {
            ic_cdk::println!("Rate-limit config is already initialized");
        }
        // Spawn periodic job of fetching latest API boundary node topology
        // API boundary nodes are authorized readers of all config rules (including not yet disclosed ones)
        periodically_poll_api_boundary_nodes(
            init_arg.registry_polling_period_secs,
            Arc::new(state),
        );
    });
    ic_cdk::println!("Finished canister init");
}

#[post_upgrade]
fn post_upgrade(init_arg: InitArg) {
    ic_cdk::println!("Starting canister post-upgrade");
    init(init_arg);
    // Set metric to track last upgrade time.
    let current_time = ic_cdk::api::time() as i64;
    LAST_CANISTER_UPGRADE_GAUGE.with(|cell| {
        cell.borrow_mut().set(current_time);
    });
    ic_cdk::println!("Finished canister post-upgrade");
}

#[query]
fn get_config(version: Option<Version>) -> GetConfigResponse {
    let caller_id = ic_cdk::api::caller();
    let response = with_canister_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id, state.clone());
        let formatter = ConfigConfidentialityFormatter;
        let fetcher = ConfigFetcher::new(state, formatter, access_resolver);
        fetcher.fetch(version)
    })?;
    Ok(response)
}

#[query]
fn get_rule_by_id(rule_id: RuleId) -> GetRuleByIdResponse {
    let caller_id = ic_cdk::api::caller();
    let response = with_canister_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id, state.clone());
        let formatter = RuleConfidentialityFormatter;
        let fetcher = RuleFetcher::new(state, formatter, access_resolver);
        fetcher.fetch(rule_id)
    })?;
    Ok(response)
}

#[update]
fn add_config(config: InputConfig) -> AddConfigResponse {
    let caller_id = ic_cdk::api::caller();
    let current_time = ic_cdk::api::time();
    with_canister_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id, state.clone());
        let adder = ConfigAdder::new(state);
        let adder = WithAuthorization::new(adder, access_resolver);
        let adder = WithMetrics::new(adder);
        adder.add_config(config, current_time)
    })?;
    Ok(())
}

#[update]
fn disclose_rules(args: DiscloseRulesArg) -> DiscloseRulesResponse {
    let caller_id = ic_cdk::api::caller();
    let current_time = ic_cdk::api::time();
    with_canister_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id, state.clone());
        let discloser = RulesDiscloser::new(state);
        let discloser = WithAuthorization::new(discloser, access_resolver);
        let discloser = WithMetrics::new(discloser);
        discloser.disclose_rules(args, current_time)
    })?;
    Ok(())
}

// TODO: adjust quota
#[query(decoding_quota = 10000)]
fn http_request(request: HttpRequest) -> HttpResponse {
    match request.path() {
        "/metrics" => with_metrics_registry(|registry| export_metrics_as_http_response(registry)),
        _ => HttpResponseBuilder::not_found().build(),
    }
}

fn periodically_poll_api_boundary_nodes(interval: u64, canister_api: Arc<dyn CanisterApi>) {
    let interval = Duration::from_secs(interval);

    ic_cdk_timers::set_timer_interval(interval, move || {
        let canister_api = canister_api.clone();
        ic_cdk::spawn(async move {
            let canister_id = Principal::from(REGISTRY_CANISTER_ID);
            match call::<_, (Result<Vec<ApiBoundaryNodeIdRecord>, String>,)>(
                canister_id,
                REGISTRY_CANISTER_METHOD,
                (&GetApiBoundaryNodeIdsRequest {},),
            )
            .await
            {
                Ok((Ok(api_bn_records),)) => {
                    // Set authorized readers of the rate-limit config.
                    canister_api.set_api_boundary_nodes_principals(
                        api_bn_records.into_iter().filter_map(|n| n.id).collect(),
                    );
                    // Update metrics.
                    let current_time = ic_cdk::api::time() as i64;
                    LAST_SUCCESSFUL_REGISTRY_POLL_GAUGE.with(|cell| {
                        cell.borrow_mut().set(current_time);
                    });
                }
                Ok((Err(err),)) => {
                    ic_cdk::println!("Error fetching API boundary nodes: {}", err);
                }
                Err(err) => {
                    ic_cdk::println!("Error calling registry canister: {:?}", err);
                }
            }
        });
    });
}
