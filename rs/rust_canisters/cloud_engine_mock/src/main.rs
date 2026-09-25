//! A mock for the cloud engine canisters that a cloud engine node relies on.
//!
//! It serves both roles: engine management canister and engine operator canister.
//! It serves all three endpoints the orchestrator reads and nothing else.
//! The records mirror the real interfaces field for field.
//!
//! The `set_*` updates decide what the next read answers, so a test can drive
//! the complete, incomplete and not-yet-authorized cases.

use candid::{CandidType, Principal};
use ic_cdk::{query, update};
use serde::Deserialize;
use std::cell::RefCell;

#[derive(CandidType, Deserialize, Clone, Default)]
struct HttpGatewayConfig {
    base_domains: Option<Vec<String>>,
    dns_api_urls: Option<Vec<String>>,
    dns_api_key: Option<String>,
}

#[derive(CandidType, Deserialize, Clone, Default)]
struct AcmeCredentials {
    id: Option<String>,
    key_pkcs8: Option<String>,
    directory: Option<String>,
}

#[derive(CandidType, Deserialize)]
struct GetEngineOperatorBySubnetArgs {
    subnet_id: Option<Principal>,
}

#[derive(CandidType, Deserialize, Clone, Default)]
struct GetEngineOperatorBySubnetResult {
    engine_operator_id: Option<Principal>,
}

#[derive(CandidType, Deserialize)]
enum Error {
    Unauthorized,
    NotFound,
    BadRequest(String),
    Internal(String),
}

#[derive(CandidType, Deserialize)]
enum Response<T> {
    #[serde(rename = "ok")]
    Ok(T),
    #[serde(rename = "err")]
    Err(Error),
}

#[derive(Default)]
struct State {
    config: HttpGatewayConfig,
    acme: AcmeCredentials,
    unauthorized: bool,
    /// The one (subnet, operator) pair this canister knows, when acting as
    /// the engine management canister.
    engine_operator: Option<(Principal, Principal)>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

#[query(name = "getHttpGatewayConfig")]
fn get_http_gateway_config() -> Response<HttpGatewayConfig> {
    STATE.with_borrow(|state| {
        if state.unauthorized {
            Response::Err(Error::Unauthorized)
        } else {
            Response::Ok(state.config.clone())
        }
    })
}

#[query(name = "getHttpGatewayAcmeCredentials")]
fn get_http_gateway_acme_credentials() -> Response<AcmeCredentials> {
    STATE.with_borrow(|state| {
        if state.unauthorized {
            Response::Err(Error::Unauthorized)
        } else {
            Response::Ok(state.acme.clone())
        }
    })
}

/// The engine management canister's side: a subnet it knows nothing about
/// gets an answer with no operator in it, not an error.
#[query(name = "getEngineOperatorBySubnet")]
fn get_engine_operator_by_subnet(
    args: GetEngineOperatorBySubnetArgs,
) -> GetEngineOperatorBySubnetResult {
    STATE.with_borrow(|state| GetEngineOperatorBySubnetResult {
        engine_operator_id: state
            .engine_operator
            .filter(|(subnet, _)| Some(*subnet) == args.subnet_id)
            .map(|(_, operator)| operator),
    })
}

#[update]
fn set_engine_operator(subnet_id: Principal, engine_operator_id: Principal) {
    STATE.with_borrow_mut(|state| state.engine_operator = Some((subnet_id, engine_operator_id)));
}

#[update]
fn set_config(config: HttpGatewayConfig) {
    STATE.with_borrow_mut(|state| state.config = config);
}

#[update]
fn set_acme_credentials(acme: AcmeCredentials) {
    STATE.with_borrow_mut(|state| state.acme = acme);
}

#[update]
fn set_unauthorized(unauthorized: bool) {
    STATE.with_borrow_mut(|state| state.unauthorized = unauthorized);
}

fn main() {}
