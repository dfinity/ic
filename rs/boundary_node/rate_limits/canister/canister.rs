use access_control::AccessLevelResolver;
use add_config::{AddsConfig, ConfigAdder};
use candid::candid_method;
use confidentiality_formatting::ConfidentialityFormatterFactory;
use disclose::{DisclosesRules, RulesDiscloser};
use fetcher::{ConfigFetcher, EntityFetcher, RuleFetcher};
use ic_cdk_macros::{init, query, update};
use rate_limits_api::{
    AddConfigResponse, DiscloseRulesArg, DiscloseRulesResponse, GetConfigResponse,
    GetRuleByIdResponse, InitArg, InputConfig, RuleId, Version,
};
use state::{init_version_and_config, with_state};
mod access_control;
mod add_config;
mod confidentiality_formatting;
mod disclose;
mod fetcher;
mod state;
mod storage;
mod types;

#[init]
#[candid_method(init)]
fn init(_init_arg: InitArg) {
    // Initialize an empty config with version=1
    init_version_and_config(1);
    // TODO: init periodic timer for fetching API BNs principals.
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
