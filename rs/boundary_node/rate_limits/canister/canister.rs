use crate::access_control::{AccessLevelResolver, WithAuthorization};
use crate::add_config::{AddsConfig, ConfigAdder};
use crate::confidentiality_formatting::{
    ConfigConfidentialityFormatter, RuleConfidentialityFormatter,
};
use crate::disclose::{DisclosesRules, RulesDiscloser};
use crate::fetcher::{ConfigFetcher, EntityFetcher, IncidentFetcher, RuleFetcher};
use crate::metrics::{
    export_metrics_as_http_response, with_metrics_registry, WithMetrics, LAST_CANISTER_CHANGE_TIME,
    LAST_SUCCESSFUL_REGISTRY_POLL_TIME, REGISTRY_POLL_CALLS_COUNTER,
};
use crate::state::{init_version_and_config, with_canister_state, CanisterApi};
use candid::Principal;
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk::api::call::call;
use ic_cdk_macros::{init, inspect_message, post_upgrade, query, update};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use rate_limits_api::{
    AddConfigResponse, ApiBoundaryNodeIdRecord, DiscloseRulesArg, DiscloseRulesResponse,
    GetApiBoundaryNodeIdsRequest, GetConfigResponse, GetRuleByIdResponse,
    GetRulesByIncidentIdResponse, IncidentId, InitArg, InputConfig, RuleId, Version,
};
use std::{sync::Arc, time::Duration};

const REGISTRY_CANISTER_METHOD: &str = "get_api_boundary_node_ids";
const UPDATE_METHODS: [&str; 2] = ["add_config", "disclose_rules"];
const REPLICATED_QUERY_METHOD: &str = "get_config";

// Inspect the ingress messages in the pre-consensus phase and reject early, if the conditions are not met
#[inspect_message]
fn inspect_message() {
    // In order for this hook to succeed, accept_message() must be invoked.
    let caller_id: Principal = ic_cdk::api::caller();
    let called_method = ic_cdk::api::call::method_name();

    let (has_full_access, has_full_read_access) = with_canister_state(|state| {
        let authorized_principal = state.get_authorized_principal();
        (
            Some(caller_id) == authorized_principal,
            state.is_api_boundary_node_principal(&caller_id),
        )
    });

    if called_method == REPLICATED_QUERY_METHOD {
        if has_full_access || has_full_read_access {
            ic_cdk::api::call::accept_message();
        }
    } else if UPDATE_METHODS.contains(&called_method.as_str()) {
        if has_full_access {
            ic_cdk::api::call::accept_message();
        } else {
            ic_cdk::api::trap("message_inspection_failed: unauthorized caller");
        }
    } else {
        // All others calls are rejected
        ic_cdk::api::trap(
            "message_inspection_failed: method call is prohibited in the current context",
        );
    }
}

// Run when the canister is first installed
#[init]
fn init(init_arg: InitArg) {
    let current_time = ic_cdk::api::time();
    with_canister_state(|state| {
        // Set authorized principal, which performs write operations, such as adding new configurations
        if let Some(principal) = init_arg.authorized_principal {
            state.set_authorized_principal(principal);
        }
        // Initialize config only on the very first invocation
        if state.get_version().is_none() {
            init_version_and_config(current_time, state.clone());
        }
        // Spawn periodic job of fetching latest API boundary node topology
        // API boundary nodes are authorized readers of all config rules (including not yet disclosed ones)
        periodically_poll_api_boundary_nodes(
            init_arg.registry_polling_period_secs,
            Arc::new(state),
        );
    });
    // Update metric.
    LAST_CANISTER_CHANGE_TIME.with(|cell| {
        cell.borrow_mut().set(current_time as i64);
    });
}

// Run every time a canister is upgraded
#[post_upgrade]
fn post_upgrade(init_arg: InitArg) {
    // Run the same initialization logic
    init(init_arg);
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

#[query]
fn get_rules_by_incident_id(incident_id: IncidentId) -> GetRulesByIncidentIdResponse {
    let caller_id = ic_cdk::api::caller();
    let response = with_canister_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id, state.clone());
        let formatter = RuleConfidentialityFormatter;
        let fetcher = IncidentFetcher::new(state, formatter, access_resolver);
        fetcher.fetch(incident_id)
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

#[query(decoding_quota = 10000)]
fn http_request(request: HttpRequest) -> HttpResponse {
    match request.path() {
        "/metrics" => with_canister_state(|state| {
            with_metrics_registry(|registry| export_metrics_as_http_response(registry, state))
        }),
        _ => HttpResponseBuilder::not_found().build(),
    }
}

fn periodically_poll_api_boundary_nodes(interval: u64, canister_api: Arc<dyn CanisterApi>) {
    let interval = Duration::from_secs(interval);

    ic_cdk_timers::set_timer_interval(interval, move || {
        let canister_api = canister_api.clone();
        ic_cdk::spawn(async move {
            let canister_id = Principal::from(REGISTRY_CANISTER_ID);

            let (call_status, message) =
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
                        LAST_SUCCESSFUL_REGISTRY_POLL_TIME.with(|cell| {
                            cell.borrow_mut().set(current_time);
                        });
                        ("success", "")
                    }
                    Ok((Err(_),)) => ("failure", "calling_canister_method_failed"),
                    Err(_) => ("failure", "canister_call_rejected"),
                };

            // Update metric.
            REGISTRY_POLL_CALLS_COUNTER.with(|cell| {
                let metric = cell.borrow_mut();
                metric.with_label_values(&[call_status, message]).inc();
            });
        });
    });
}
