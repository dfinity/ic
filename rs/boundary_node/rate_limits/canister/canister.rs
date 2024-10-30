use std::{collections::HashSet, time::Duration};

use crate::access_control::AccessLevelResolver;
use crate::add_config::{AddsConfig, ConfigAdder};
use crate::confidentiality_formatting::ConfidentialityFormatterFactory;
use crate::disclose::{DisclosesRules, RulesDiscloser};
use crate::fetcher::{ConfigFetcher, EntityFetcher, RuleFetcher};
use crate::metrics::{encode_metrics, serve_metrics};
use crate::state::Repository;
use crate::state::{init_version_and_config, with_state};
use crate::storage::API_BOUNDARY_NODE_PRINCIPALS;
use candid::{candid_method, Principal};
use ic_canisters_http_types::{HttpRequest, HttpResponse, HttpResponseBuilder};
use ic_cdk::api::call::call;
use ic_cdk_macros::{init, query, update};
use rate_limits_api::{
    AddConfigResponse, ApiBoundaryNodeIdRecord, DiscloseRulesArg, DiscloseRulesResponse,
    GetApiBoundaryNodeIdsRequest, GetConfigResponse, GetRuleByIdResponse, InitArg, InputConfig,
    RuleId, Version,
};

const REGISTRY_CANISTER_ID: &str = "rwlgt-iiaaa-aaaaa-aaaaa-cai";
const REGISTRY_CANISTER_METHOD: &str = "get_api_boundary_node_ids";

// TODO: implement proper canister lifecycle: upgrade, post_upgrade, ...
#[init]
#[candid_method(init)]
fn init(init_arg: InitArg) {
    // Set authorized principal, which performs write operations, such as adding new configurations
    if let Some(principal) = init_arg.authorized_principal {
        with_state(|state| {
            state.set_authorized_principal(principal);
        });
    }
    // Initialize an empty config corresponding to version=1
    init_version_and_config(1);
    // Spawn periodic job of fetching latest API boundary node topology
    // API boundary nodes are authorized readers of all config rules (including not yet disclosed ones)
    periodically_poll_api_boundary_nodes(init_arg.registry_polling_period_secs);
}

#[query]
#[candid_method(query)]
fn get_config(version: Option<Version>) -> GetConfigResponse {
    let caller_id = ic_cdk::api::caller();
    let response = with_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id, state.clone());
        let formatter =
            ConfidentialityFormatterFactory::new(access_resolver).create_config_formatter();
        let fetcher = ConfigFetcher::new(state, formatter);
        fetcher.fetch(version)
    })?;
    Ok(response.into())
}

#[query]
#[candid_method(query)]
fn get_rule_by_id(rule_id: RuleId) -> GetRuleByIdResponse {
    let caller_id = ic_cdk::api::caller();
    let response = with_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id, state.clone());
        let formatter =
            ConfidentialityFormatterFactory::new(access_resolver).create_rule_formatter();
        let fetcher = RuleFetcher::new(state, formatter);
        fetcher.fetch(rule_id)
    })?;
    Ok(response.into())
}

#[update]
#[candid_method(update)]
fn add_config(config: InputConfig) -> AddConfigResponse {
    let caller_id = ic_cdk::api::caller();
    let current_time = ic_cdk::api::time();
    with_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id, state.clone());
        let writer = ConfigAdder::new(state, access_resolver);
        writer.add_config(config.into(), current_time)
    })?;
    Ok(())
}

#[update]
#[candid_method(update)]
fn disclose_rules(args: DiscloseRulesArg) -> DiscloseRulesResponse {
    let caller_id = ic_cdk::api::caller();
    with_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id, state.clone());
        let discloser = RulesDiscloser::new(state, access_resolver);
        discloser.disclose_rules(args.into())
    })?;
    Ok(())
}

// TODO: adjust quota
#[query(decoding_quota = 10000)]
#[candid_method(query)]
fn http_request(request: HttpRequest) -> HttpResponse {
    match request.path() {
        "/metrics" => serve_metrics(ic_cdk::api::time() as i64, encode_metrics),
        _ => HttpResponseBuilder::not_found().build(),
    }
}

fn periodically_poll_api_boundary_nodes(interval: u64) {
    let interval = Duration::from_secs(interval);

    ic_cdk_timers::set_timer_interval(interval, || {
        ic_cdk::spawn(async {
            if let Ok(canister_id) = Principal::from_text(REGISTRY_CANISTER_ID) {
                match call::<_, (Result<Vec<ApiBoundaryNodeIdRecord>, String>,)>(
                    canister_id,
                    REGISTRY_CANISTER_METHOD,
                    (&GetApiBoundaryNodeIdsRequest {},),
                )
                .await
                {
                    Ok((Ok(api_bn_records),)) => {
                        API_BOUNDARY_NODE_PRINCIPALS.with(|cell| {
                            *cell.borrow_mut() =
                                HashSet::from_iter(api_bn_records.into_iter().filter_map(|n| n.id))
                        });
                    }
                    Ok((Err(err),)) => {
                        ic_cdk::println!("Error fetching API boundary nodes: {}", err);
                    }
                    Err(err) => {
                        ic_cdk::println!("Error calling registry canister: {:?}", err);
                    }
                }
            } else {
                ic_cdk::println!("Failed to parse registry_canister_id");
            }
        });
    });
}
