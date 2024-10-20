use std::{collections::HashSet, time::Duration};

use access_control::AccessLevelResolver;
use add_config::{AddsConfig, ConfigAdder};
use candid::{candid_method, Principal};
use confidentiality_formatting::ConfidentialityFormatterFactory;
use disclose::{DisclosesRules, RulesDiscloser};
use fetcher::{ConfigFetcher, EntityFetcher, RuleFetcher};
use ic_cdk::api::call::call;
use ic_cdk_macros::{init, query, update};
use rate_limits_api::{
    AddConfigResponse, ApiBoundaryNodeIdRecord, DiscloseRulesArg, DiscloseRulesResponse,
    GetApiBoundaryNodeIdsRequest, GetConfigResponse, GetRuleByIdResponse, InitArg, InputConfig,
    RuleId, Version,
};
use state::{init_version_and_config, with_state};
use storage::API_BOUNDARY_NODE_PRINCIPALS;
mod access_control;
mod add_config;
mod confidentiality_formatting;
mod disclose;
mod fetcher;
mod state;
mod storage;
mod types;

const REGISTRY_CANISTER_ID: &str = "rwlgt-iiaaa-aaaaa-aaaaa-cai";
const REGISTRY_CANISTER_METHOD: &str = "get_api_boundary_node_ids";

#[init]
#[candid_method(init)]
fn init(init_arg: InitArg) {
    // Initialize an empty config with version=1
    init_version_and_config(1);

    let interval = std::time::Duration::from_secs(init_arg.registry_polling_period_secs);

    periodically_fetch_api_boundary_nodes_set(interval);
}

#[query(name = "get_config")]
#[candid_method(query)]
fn get_config(version: Option<Version>) -> GetConfigResponse {
    let caller_id = ic_cdk::api::caller();
    let response = with_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id);
        let formatter =
            ConfidentialityFormatterFactory::new(access_resolver).create_config_formatter();
        let fetcher = ConfigFetcher::new(state, formatter);
        fetcher.fetch(version)
    })?;
    Ok(response.into())
}

#[query(name = "get_rule_by_id")]
#[candid_method(query)]
fn get_rule_by_id(rule_id: RuleId) -> GetRuleByIdResponse {
    let caller_id = ic_cdk::api::caller();
    let response = with_state(|state| {
        let access_resolver = AccessLevelResolver::new(caller_id);
        let formatter =
            ConfidentialityFormatterFactory::new(access_resolver).create_rule_formatter();
        let fetcher = RuleFetcher::new(state, formatter);
        fetcher.fetch(rule_id)
    })?;
    Ok(response.into())
}

#[update(name = "add_config")]
#[candid_method(update)]
fn add_config(config: InputConfig) -> AddConfigResponse {
    let caller_id = ic_cdk::api::caller();
    with_state(|state| {
        let access_resolver: AccessLevelResolver = AccessLevelResolver::new(caller_id);
        let writer = ConfigAdder::new(state, access_resolver);
        writer.add_config(config.into())
    })?;
    Ok(())
}

#[update(name = "disclose_rules")]
#[candid_method(update)]
fn disclose_rules(args: DiscloseRulesArg) -> DiscloseRulesResponse {
    let caller_id = ic_cdk::api::caller();
    with_state(|state| {
        let access_resolver: AccessLevelResolver = AccessLevelResolver::new(caller_id);
        let discloser = RulesDiscloser::new(state, access_resolver);
        discloser.disclose_rules(args.into())
    })?;
    Ok(())
}

fn periodically_fetch_api_boundary_nodes_set(interval: Duration) {
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
                    Ok((Ok(api_bns_count),)) => {
                        API_BOUNDARY_NODE_PRINCIPALS.with(|cell| {
                            *cell.borrow_mut() =
                                HashSet::from_iter(api_bns_count.into_iter().filter_map(|n| n.id))
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
