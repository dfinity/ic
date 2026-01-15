#![allow(unused_imports)]
#![allow(deprecated)]

use crate::access_control::{AccessLevelResolver, WithAuthorization};
use crate::add_config::{AddsConfig, ConfigAdder};
use crate::confidentiality_formatting::{
    ConfigConfidentialityFormatter, RuleConfidentialityFormatter,
};
use crate::disclose::{DisclosesRules, RulesDiscloser};
use crate::getter::{ConfigGetter, EntityGetter, IncidentGetter, RuleGetter};
use crate::logs::{self, Log, LogEntry, P0, Priority};
use crate::metrics::{
    METRICS, WithMetrics, export_metrics_as_http_response, with_metrics_registry,
};
use crate::state::{CanisterApi, init_version_and_config, with_canister_state};
use candid::Principal;
use ic_canister_log::{export as export_logs, log};
use ic_cdk::api::call::call;
use ic_cdk::{init, inspect_message, post_upgrade, query, update};
use ic_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_nns_constants::REGISTRY_CANISTER_ID;
use rate_limits_api::{
    AddConfigResponse, ApiBoundaryNodeIdRecord, DiscloseRulesArg, DiscloseRulesResponse,
    GetApiBoundaryNodeIdsRequest, GetConfigResponse, GetRuleByIdResponse,
    GetRulesByIncidentIdResponse, IncidentId, InitArg, InputConfig, RuleId, Version,
};
use std::{borrow::BorrowMut, str::FromStr, sync::Arc, time::Duration};

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
        } else {
            ic_cdk::api::trap(
                "message_inspection_failed: method call is prohibited in the current context",
            );
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
    METRICS.with(|cell| {
        let mut cell = cell.borrow_mut();
        cell.last_canister_change_time
            .borrow_mut()
            .set(current_time as i64);
    });
}

// Run every time a canister is upgraded
#[post_upgrade]
fn post_upgrade(init_arg: InitArg) {
    // Run the same initialization logic
    init(init_arg);
}

/// Retrieves the rate-limit configuration from the canister, applying confidentiality formatting based on caller's access level and rules confidentiality statuses
///
/// This query method fetches either the latest configuration or a specific version, if provided in the input.
/// The response includes the config containing all rate-limit rules and the JSON schema version needed for decoding the rules.
#[query]
fn get_config(version: Option<Version>) -> GetConfigResponse {
    let caller_id = ic_cdk::api::caller();
    let response = with_canister_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id, state.clone());
        let formatter = ConfigConfidentialityFormatter;
        let getter = ConfigGetter::new(state, formatter, access_resolver);
        getter.get(&version)
    })?;
    Ok(response)
}

/// Retrieves a specific rate-limit rule by its ID, applying confidentiality formatting, based on caller's access level and rule's confidentiality status
#[query]
fn get_rule_by_id(rule_id: RuleId) -> GetRuleByIdResponse {
    let caller_id = ic_cdk::api::caller();
    let response = with_canister_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id, state.clone());
        let formatter = RuleConfidentialityFormatter;
        let getter = RuleGetter::new(state, formatter, access_resolver);
        getter.get(&rule_id)
    })?;
    Ok(response)
}

/// Retrieves all rate-limit rules associated with a specific incident ID, applying confidentiality formatting, based on caller's access level and rule's confidentiality status
#[query]
fn get_rules_by_incident_id(incident_id: IncidentId) -> GetRulesByIncidentIdResponse {
    let caller_id = ic_cdk::api::caller();
    let response = with_canister_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id, state.clone());
        let formatter = RuleConfidentialityFormatter;
        let getter = IncidentGetter::new(state, formatter, access_resolver);
        getter.get(&incident_id)
    })?;
    Ok(response)
}

/// Adds a new rate-limit configuration (containing a vector of rate-limit rules) to the canister
///
/// Newly added configuration (including confidential rate-limit rules) can be retrieved by the API boundary nodes and enforced on their side.
/// This update method includes authorization check and metrics collection.
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

/// Makes specified rules publicly accessible for viewing
///
/// This update method allows authorized callers to disclose rules or incidents (collection of rules),
/// making them viewable by the public. It includes authorization check and metrics collection.
#[update]
fn disclose_rules(args: DiscloseRulesArg) -> DiscloseRulesResponse {
    let caller_id = ic_cdk::api::caller();
    let disclose_time = ic_cdk::api::time();
    with_canister_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id, state.clone());
        let discloser = RulesDiscloser::new(state);
        let discloser = WithAuthorization::new(discloser, access_resolver);
        let discloser = WithMetrics::new(discloser);
        discloser.disclose_rules(args, disclose_time)
    })?;
    Ok(())
}

#[query(
    hidden = true,
    decode_with = "candid::decode_one_with_decoding_quota::<100000,_>"
)]
fn http_request(request: HttpRequest) -> HttpResponse {
    match request.path() {
        "/metrics" => with_canister_state(|state| {
            with_metrics_registry(|registry| export_metrics_as_http_response(registry, state))
        }),
        "/logs" => {
            use serde_json;

            let max_skip_timestamp = match request.raw_query_param("time") {
                Some(arg) => match u64::from_str(arg) {
                    Ok(value) => value,
                    Err(_) => {
                        return HttpResponseBuilder::bad_request()
                            .with_body_and_content_length("failed to parse the 'time' parameter")
                            .build();
                    }
                },
                None => 0,
            };

            let mut entries: Log = Default::default();
            for entry in export_logs(&logs::P0) {
                entries.entries.push(LogEntry {
                    timestamp: entry.timestamp,
                    counter: entry.counter,
                    priority: Priority::P0,
                    file: entry.file.to_string(),
                    line: entry.line,
                    message: entry.message,
                });
            }
            for entry in export_logs(&logs::P1) {
                entries.entries.push(LogEntry {
                    timestamp: entry.timestamp,
                    counter: entry.counter,
                    priority: Priority::P1,
                    file: entry.file.to_string(),
                    line: entry.line,
                    message: entry.message,
                });
            }
            entries
                .entries
                .retain(|entry| entry.timestamp >= max_skip_timestamp);
            HttpResponseBuilder::ok()
                .header("Content-Type", "application/json; charset=utf-8")
                .with_body_and_content_length(serde_json::to_string(&entries).unwrap_or_default())
                .build()
        }
        _ => HttpResponseBuilder::not_found().build(),
    }
}

// Manually add a dummy method so that the Candid interface can be properly generated:
//   `http_request: (HttpRequest) -> (HttpResponse) query;`
// Without this dummy method, it will be `http_request: (blob) -> (HttpResponse) query;`
// because of the `decode_with` option used above.
#[::candid::candid_method(query, rename = "http_request")]
#[allow(unused_variables)]
fn __candid_method_http_request(request: HttpRequest) -> HttpResponse {
    panic!("candid dummy function called")
}

fn periodically_poll_api_boundary_nodes(interval: u64, canister_api: Arc<dyn CanisterApi>) {
    let interval = Duration::from_secs(interval);

    ic_cdk_timers::set_timer_interval(interval, move || {
        let canister_api = canister_api.clone();

        async move {
            let canister_id = Principal::from(REGISTRY_CANISTER_ID);

            let (call_status, message) = match call::<
                _,
                (Result<Vec<ApiBoundaryNodeIdRecord>, String>,),
            >(
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
                    // Update metric.
                    let current_time = ic_cdk::api::time() as i64;
                    METRICS.with(|cell| {
                        let mut cell = cell.borrow_mut();
                        cell.last_successful_registry_poll_time
                            .borrow_mut()
                            .set(current_time);
                    });
                    ("success", "")
                }
                Ok((Err(err),)) => {
                    log!(
                        P0,
                        "[poll_api_boundary_nodes]: failed to fetch nodes from registry {err:?}",
                    );
                    ("failure", "calling_canister_method_failed")
                }
                Err(err) => {
                    log!(
                        P0,
                        "[poll_api_boundary_nodes]: failed to fetch nodes from registry {err:?}",
                    );
                    ("failure", "canister_call_rejected")
                }
            };

            // Update metric.
            METRICS.with(|cell| {
                let mut cell = cell.borrow_mut();
                cell.registry_poll_calls
                    .borrow_mut()
                    .with_label_values(&[call_status, message])
                    .inc();
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_candid_interface_compatibility() {
        use candid_parser::utils::{CandidSource, service_equal};

        fn source_to_str(source: &CandidSource) -> String {
            match source {
                CandidSource::File(f) => {
                    std::fs::read_to_string(f).unwrap_or_else(|_| "".to_string())
                }
                CandidSource::Text(t) => t.to_string(),
            }
        }

        fn check_service_equal(
            new_name: &str,
            new: CandidSource,
            old_name: &str,
            old: CandidSource,
        ) {
            let new_str = source_to_str(&new);
            let old_str = source_to_str(&old);
            match service_equal(new, old) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "{new_name} is not compatible with {old_name}!\n\n\
                {new_name}:\n\
                {new_str}\n\n\
                {old_name}:\n\
                {old_str}\n"
                    );
                    panic!("{e:?}");
                }
            }
        }

        candid::export_service!();

        let new_interface = __export_service();

        // check the public interface against the actual one
        let old_interface = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
            .join("canister/interface.did");

        check_service_equal(
            "actual rate-limit candid interface",
            candid_parser::utils::CandidSource::Text(&new_interface),
            "declared candid interface in interface.did file",
            candid_parser::utils::CandidSource::File(old_interface.as_path()),
        );
    }
}
