use candid::CandidType;
use candid::Principal;
use ic_cdk::api::call::call;
use ic_cdk::api::time;
use serde_json::Value;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
type Id = String;
type Version = u64;
type Timestamp = u64;

const REGISTRY_CANISTER_ID: &str = "rwlgt-iiaaa-aaaaa-aaaaa-cai";
const REGISTRY_CANISTER_METHOD: &str = "get_api_boundary_node_ids";

static API_BNS_COUNT: AtomicU64 = AtomicU64::new(0);

#[derive(CandidType, candid::Deserialize)]
pub struct GetApiBoundaryNodeIdsRequest {}

#[derive(CandidType, candid::Deserialize)]
struct ConfigResponse {
    version: Version,
    active_since: Timestamp,
    config: OutputConfig,
}

type GetConfigResponse = Result<ConfigResponse, String>;
type OverwriteConfigResponse = Result<(), String>;
type DisclosesRulesResponse = Result<(), String>;

#[derive(Clone)]
struct StoredConfig {
    active_since: Timestamp,
    rules: Vec<InputRule>,
}

#[derive(CandidType, candid::Deserialize, Clone)]
struct OutputConfig {
    rules: Vec<OutputRule>,
}

#[derive(CandidType, candid::Deserialize, Clone)]
struct InputConfig {
    rules: Vec<InputRule>,
}

#[derive(CandidType, candid::Deserialize, Clone)]
struct InputRule {
    id: Id,
    rule_raw: Vec<u8>,
    description: String,
}

#[derive(CandidType, candid::Deserialize, Clone)]
struct OutputRule {
    id: Id,
    rule_raw: Option<Vec<u8>>,
    description: Option<String>,
}

thread_local! {
    static VERSION: RefCell<Version> = RefCell::new(0);
    static CONFIGS: RefCell<HashMap<Version, StoredConfig>> = RefCell::new(HashMap::new());
}

#[ic_cdk::query]
fn get_api_boundary_nodes_count() -> u64 {
    API_BNS_COUNT.load(Ordering::Relaxed)
}

#[ic_cdk_macros::update]
fn overwrite_config(config: InputConfig) -> OverwriteConfigResponse {
    let version = VERSION.with(|v| {
        *v.borrow_mut() += 1;
        v.borrow().clone()
    });

    // check json schema
    for rule in config.rules.iter() {
        let rule_raw = String::from_utf8(rule.rule_raw.clone()).unwrap();
        assert!(serde_json::from_str::<Value>(&rule_raw).is_ok())
    }

    let new_config = StoredConfig {
        active_since: time(),
        rules: config.rules,
    };

    CONFIGS.with(|p| {
        let mut configs = p.borrow_mut();
        configs.insert(version, new_config);
    });

    Ok(())
}

#[ic_cdk_macros::update]
fn get_config(version: Option<Version>) -> GetConfigResponse {
    let version = version.unwrap_or(VERSION.with(|v| v.borrow().clone()));

    let configs = CONFIGS.with(|configs| configs.borrow().clone());

    let config = configs.get(&version).unwrap();

    let rules = config
        .rules
        .iter()
        .map(|r| OutputRule {
            id: r.id.clone(),
            description: Some(r.description.clone()),
            rule_raw: Some(r.rule_raw.clone()),
        })
        .collect();

    let output_config = OutputConfig { rules };

    Ok(ConfigResponse {
        active_since: config.active_since,
        version: version,
        config: output_config,
    })
}

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
