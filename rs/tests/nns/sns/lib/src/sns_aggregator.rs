use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use candid::{Decode, Principal};
use ic_agent::Agent;
use ic_registry_subnet_type::SubnetType;
use ic_sns_swap::pb::v1::{GetStateResponse, Params};
use ic_system_test_driver::canister_agent::HasCanisterAgentCapability;
use ic_system_test_driver::{
    canister_agent::CanisterAgent,
    canister_api::{CallMode, SnsRequestProvider},
    canister_requests,
    generic_workload_engine::{
        engine::Engine,
        metrics::{LoadTestMetrics, RequestOutcome},
    },
    sns_client::{SnsClient, openchat_create_service_nervous_system_proposal},
};
use ic_system_test_driver::{
    driver::{
        ic::InternetComputer,
        test_env::{TestEnv, TestEnvAttribute},
        test_env_api::{
            GetFirstHealthyNodeSnapshot, HasPublicApiUrl, HasTopologySnapshot, IcNodeContainer,
            get_dependency_path, load_wasm,
        },
    },
    util::block_on,
};
use ic_utils::{
    call::SyncCall,
    interfaces::{HttpRequestCanister, ManagementCanister, http_request::HttpResponse},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use slog::{Logger, info};

use super::sns_deployment::{self, SnsSaleParticipants, install_nns, install_sns};

use ic_base_types::PrincipalId;

use anyhow::Result;

// Taken from https://github.com/dfinity/nns-dapp/blob/main/frontend/src/lib/constants/sns.constants.ts
const AGGREGATOR_CANISTER_PATH: &str = "/sns/list/latest/slow.json";
const AGGREGATOR_CANISTER_VERSION: &str = "v1";

// Using the current workload generator to measure update call durations e2e requires setting this to "infinity"
// as we should never stop awaiting the execution completion (unless the overall workload timeout controlled
// by `RESPONSES_COLLECTION_EXTRA_TIMEOUT` is reached).
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(1_000);

fn config_for_security_testing(env: &TestEnv) {
    InternetComputer::new()
        .add_fast_single_node_subnet(SubnetType::System)
        .add_fast_single_node_subnet(SubnetType::Application)
        .setup_and_start(env)
        .expect("failed to setup IC under test");
    env.topology_snapshot().subnets().for_each(|subnet| {
        subnet
            .nodes()
            .for_each(|node| node.await_status_is_healthy().unwrap())
    });
    install_nns(env, vec![], vec![]);
    let create_service_nervous_system_proposal = openchat_create_service_nervous_system_proposal();
    install_sns(env, create_service_nervous_system_proposal);
}

pub fn benchmark_config(env: TestEnv) {
    sns_deployment::sns_setup(env);
}

pub fn benchmark_config_with_auth(env: TestEnv) {
    sns_deployment::sns_setup_with_many_sale_participants(env);
}

pub fn benchmark_config_with_aggregator(env: TestEnv) {
    sns_deployment::sns_setup(env.clone());
    install_aggregator(&env);
}

pub fn config_fast(env: TestEnv) {
    config_for_security_testing(&env);
    install_aggregator(&env);
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AggregatorClient {
    canister_id: PrincipalId,
}

impl TestEnvAttribute for AggregatorClient {
    fn attribute_name() -> String {
        "aggregator_client".to_string()
    }
}

/// A helper function to traverse JSON objects
fn walk_object(object: Value, field: String) -> Result<Value> {
    if let Value::Object(mut object) = object {
        let child = object
            .remove(&field)
            .context("cannot find expected field `{field}` in JSON: {object:?}")?;
        Ok(child)
    } else {
        bail!("unexpected JSON: {object:?}")
    }
}

/// A helper function to traverse JSON arrays
fn walk_array(array: Value, index: usize) -> Result<Value> {
    if let Value::Array(mut array) = array {
        if array.len() <= index {
            bail!(
                "array {array:?} of length {} is not defined at index `{index}`",
                array.len()
            )
        }
        let child = array.remove(index);
        Ok(child)
    } else {
        bail!("unexpected JSON: {array:?}")
    }
}

/// TODO: Reimplement this type using [`canister_api::Request<HttpResponse>`]. Avoid the [`HttpRequestCanister<'agent>`] dependency.
impl AggregatorClient {
    fn id(canister: &HttpRequestCanister) -> PrincipalId {
        PrincipalId(*canister.canister_id_())
    }

    pub fn principal(&self) -> Principal {
        Principal::from(self.canister_id)
    }

    pub fn aggregator_http_endpoint() -> String {
        format!("/{AGGREGATOR_CANISTER_VERSION}{AGGREGATOR_CANISTER_PATH}")
    }

    async fn http_get_request(
        log: &Logger,
        canister: &HttpRequestCanister<'_>,
        relative_url: String,
    ) -> Result<HttpResponse> {
        let (response,) = canister
            .http_request("GET", relative_url.clone(), vec![], vec![], None)
            .call()
            .await
            .unwrap();
        let cid = Self::id(canister).to_string();
        match response.status_code {
            200 => {
                info!(
                    log,
                    "200: response from GET `http_request` to {:?} (URL={relative_url})", cid,
                );
                Ok(response)
            }
            code => {
                bail!(
                    "{code}: response from GET `http_request` to {:?} (URL={relative_url})",
                    cid
                )
            }
        }
    }

    pub async fn http_get_favicon(
        log: &Logger,
        canister: &HttpRequestCanister<'_>,
    ) -> Result<Vec<u8>> {
        let url = "/favicon.ico".to_string();
        Self::http_get_request(log, canister, url)
            .await
            .map(|res| res.body)
    }

    pub async fn http_get_asset(
        log: &Logger,
        canister: &HttpRequestCanister<'_>,
    ) -> Result<Vec<u8>> {
        let url = Self::aggregator_http_endpoint();
        Self::http_get_request(log, canister, url)
            .await
            .map(|res| res.body)
    }

    pub async fn extract_first_sns_sale_config(
        log: &Logger,
        canister: &HttpRequestCanister<'_>,
    ) -> Result<Value> {
        let asset_bytes = Self::http_get_asset(log, canister).await.unwrap();
        let asset: Value = serde_json::from_slice(asset_bytes.as_slice())?;
        match asset {
            Value::Array(values) => {
                let sns = values
                    .into_iter()
                    .next()
                    .context("aggregator has no SNSs")?;
                match sns {
                    Value::Object(mut sns) => {
                        let swap_state = sns
                            .remove(&"swap_state".to_string())
                            .context("cannot find expected filed `swap_state` in JSON: {sns:?}")?;
                        Ok(swap_state)
                    }
                    _ => bail!("unexpected JSON: {sns:?}"),
                }
            }
            _ => {
                bail!("unexpected JSON: {asset:?}")
            }
        }
    }

    async fn sub_asset<P>(
        log: &Logger,
        canister: &HttpRequestCanister<'_>,
        extract_sub_asset: &P,
        timeout: Duration,
    ) -> RequestOutcome<Value, String>
    where
        P: Fn(Value) -> Result<Value>,
    {
        let start_time = Instant::now();
        let attempts = Arc::new(AtomicUsize::new(0));
        let result = ic_system_test_driver::retry_with_msg_async!(
            "http_get_asset",
            log,
            timeout,
            Duration::from_secs(5),
            {
                let log = log.clone();
                let attempts = attempts.clone();
                let canister = canister.clone();
                move || {
                    let log = log.clone();
                    let attempts = attempts.clone();
                    let canister = canister.clone();
                    attempts.fetch_add(1, Ordering::Relaxed);
                    async move {
                        let asset_bytes = Self::http_get_asset(&log, &canister).await?;
                        info!(&log, "Try parsing the response body ...");
                        let asset: Value = serde_json::from_slice(asset_bytes.as_slice())?;
                        extract_sub_asset(asset)
                    }
                }
            }
        )
        .await
        .map_err(|e| format!("{e:?}"));
        RequestOutcome::new(
            result,
            "aggregator_sub_asset".to_string(),
            start_time.elapsed(),
            attempts.load(Ordering::Relaxed),
        )
    }

    pub async fn first_sns_asset(
        log: &Logger,
        canister: &HttpRequestCanister<'_>,
        timeout: Duration,
    ) -> RequestOutcome<Value, String> {
        let extract_sub_asset = move |asset| {
            let sub_asset = walk_array(asset, 0)?;
            Ok(sub_asset)
        };
        Self::sub_asset(log, canister, &extract_sub_asset, timeout).await
    }

    pub async fn first_swap_params(
        log: &Logger,
        canister: &HttpRequestCanister<'_>,
        timeout: Duration,
    ) -> RequestOutcome<Value, String> {
        let extract_sub_asset = move |asset| {
            let sub_asset = walk_array(asset, 0)?;
            let sub_asset = walk_object(sub_asset, "swap_state".to_string())?;
            let sub_asset = walk_object(sub_asset, "swap".to_string())?;
            let sub_asset = walk_object(sub_asset, "params".to_string())?;
            if sub_asset.is_null() {
                bail!("Sale params are null; has the SNS token sale been started?")
            } else {
                Ok(sub_asset)
            }
        };
        Self::sub_asset(log, canister, &extract_sub_asset, timeout).await
    }

    pub fn install_aggregator_and_check_healthy(env: &TestEnv) -> Self {
        let log = env.logger();
        let app_node = env.get_first_healthy_application_node_snapshot();
        let agent = app_node.build_default_agent();
        let canister = {
            let effective_canister_id = app_node.effective_canister_id();
            info!(
                &log,
                "Validating aggregator canister's installation via public endpoint {}",
                app_node.get_public_url().as_str(),
            );
            let p = get_dependency_path("external/sns_aggregator/file/sns_aggregator_dev.wasm.gz");
            let p = std::fs::canonicalize(p.clone())
                .unwrap_or_else(|e| panic!("cannot obtain canonical path from {p:?}: {e:?}"));
            let canister_bytes = load_wasm(p);
            let canister_id = app_node.with_default_agent({
                let log = log.clone();
                move |agent| async move {
                    info!(
                        log,
                        "Preparing to install canister with effective ID {effective_canister_id:?} ..."
                    );
                    let management_canister = ManagementCanister::create(&agent);
                    let (canister_id,) = management_canister
                        .create_canister()
                        .as_provisional_create_with_amount(None)
                        .with_effective_canister_id(effective_canister_id)
                        .call_and_wait()
                        .await
                        .unwrap();
                    info!(
                        log,
                        "Successfully created canister {canister_id:?} using provisional builder"
                    );
                    management_canister
                        .install_code(&canister_id, &canister_bytes)
                        .call_and_wait()
                        .await
                        .unwrap();
                    info!(log, "Successfully installed canister {canister_id:?}");
                    canister_id
                }
            });
            HttpRequestCanister::create(&agent, canister_id)
        };

        info!(&log, "Try downloading the favicon ...");
        let _ = block_on(Self::http_get_favicon(&log, &canister)).unwrap();

        info!(log, "Aggregator canister installed!");
        let aggregator = Self {
            canister_id: Self::id(&canister),
        };
        aggregator.write_attribute(env);
        aggregator
    }

    pub fn new_http_canister<'agent>(&self, agent: &'agent Agent) -> HttpRequestCanister<'agent> {
        let principal = self.principal();
        HttpRequestCanister::create(agent, principal)
    }
}

fn install_aggregator(env: &TestEnv) {
    let log = env.logger();
    let start_time = Instant::now();
    AggregatorClient::install_aggregator_and_check_healthy(env);
    info!(
        log,
        "========== The SNS Aggregator has been installed successfully in {:?} ===========",
        start_time.elapsed()
    );
}

pub fn wait_until_aggregator_finds_sns(env: TestEnv) {
    let log = env.logger();
    let start_time = Instant::now();
    let aggregator = AggregatorClient::read_attribute(&env);
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    let http_canister = aggregator.new_http_canister(&agent);
    let sns_asset = block_on(AggregatorClient::first_sns_asset(
        &log,
        &http_canister,
        Duration::from_secs(2 * 60),
    ))
    .result()
    .unwrap();
    info!(log, "Obtained SNS asset from aggregator: {sns_asset:#}");
    info!(
        log,
        "========== The SNS Aggregator has found an SNS in {:?} ===========",
        start_time.elapsed()
    );
}

pub fn validate_aggregator_data(env: TestEnv) {
    let log = env.logger();
    let start_time = Instant::now();
    let app_node = env.get_first_healthy_application_node_snapshot();
    let agent = app_node.build_default_agent();
    let aggregator = AggregatorClient::read_attribute(&env);
    let sns_client = SnsClient::read_attribute(&env);
    block_on(async move {
        info!(log, "Fetch SNS sale params from aggregator canister ...");
        let sns_sale_params_from_aggregator = {
            let http_canister = aggregator.new_http_canister(&agent);
            let swap_params = AggregatorClient::first_swap_params(
                &log,
                &http_canister,
                Duration::from_secs(5 * 60),
            )
            .await
            .result()
            .unwrap();
            info!(
                log,
                "Obtained SNS sale parameters from aggregator: {swap_params:#}"
            );
            let reinterpreted_swap_params: Params = serde_json::from_value(swap_params).unwrap();
            reinterpreted_swap_params
        };
        info!(log, "Fetch SNS sale params from SNS sale canister ...");
        let sns_sale_params_from_sns = {
            let canister_agent = app_node.build_canister_agent().await;
            let request_provider = SnsRequestProvider::from_sns_client(&sns_client);
            let request = request_provider.get_state(CallMode::Update);
            let res = canister_agent.call(&request).await.result().unwrap();
            let res = Decode!(res.as_slice(), GetStateResponse).expect("failed to decode");
            // We've already checked above that the SNS sale params had propagated through the aggregator canister.
            // Thus, they must also be available while querying the SNS directly.
            let mut sns_sale_params = res.swap.unwrap().params.unwrap();
            let sns_sale_params_json = serde_json::to_value(sns_sale_params).unwrap();
            info!(
                log,
                "Obtained SNS sale parameters from SNS sale canister: {sns_sale_params_json:#}"
            );
            // The aggregator canister doesn't yet support `min_direct_participation_icp_e8s` and `max_direct_participation_icp_e8s`
            sns_sale_params.min_direct_participation_icp_e8s = None;
            sns_sale_params.max_direct_participation_icp_e8s = None;
            sns_sale_params
        };
        assert_eq!(
            sns_sale_params_from_aggregator, sns_sale_params_from_sns,
            "SNS Swap params from aggregator didn't match the params from the SNS Swap canister"
        );
    });
    info!(
        env.logger(),
        "========== The SNS Aggregator has detected an SNS token sale in {:?} ===========",
        start_time.elapsed()
    );
}

pub fn workload_via_aggregator(env: TestEnv, rps: usize, duration: Duration) {
    let log = env.logger();

    // --- Create a future generator ---
    let future_generator = {
        let app_node = env.get_first_healthy_application_node_snapshot();
        let agent = app_node.build_default_agent();
        let log = log.clone();
        let aggregator = AggregatorClient::read_attribute(&env);
        move |_idx| {
            let log = log.clone();
            let agent = agent.clone();
            let aggregator = aggregator.clone();
            async move {
                let agent = agent.clone();
                let http_canister = aggregator.new_http_canister(&agent);
                AggregatorClient::first_sns_asset(&log, &http_canister, Duration::from_secs(2 * 60))
                    .await
                    .map(|_| ())
                    .into_test_outcome()
            }
        }
    };

    // --- Generate workload ---
    let engine = Engine::new(log.clone(), future_generator, rps as f64, duration)
        .increase_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT);

    // --- Emit metrics ---
    let metrics = {
        let aggr = LoadTestMetrics::new(log);
        let fun = LoadTestMetrics::aggregator_fn;
        block_on(engine.execute(aggr, fun)).expect("Workload execution has failed.")
    };
    env.emit_report(format!("{metrics}"));
}

pub fn workload_direct(env: TestEnv, rps: usize, duration: Duration) {
    let log = env.logger();

    // --- Create a future generator ---
    let future_generator = {
        let agents = {
            let nns_node = env.get_first_healthy_nns_node_snapshot();
            let app_node = env.get_first_healthy_application_node_snapshot();
            block_on(async move {
                let nns_agent = nns_node.build_canister_agent().await;
                let app_agent = app_node.build_canister_agent().await;
                (nns_agent, app_agent)
            })
        };
        let request_provider = {
            let sns_client = SnsClient::read_attribute(&env);
            SnsRequestProvider::from_sns_client(&sns_client)
        };
        move |idx| {
            let agents = agents.clone();
            async move {
                let (nns_agent, app_agent) = agents.clone();
                let request_outcome = canister_requests![
                    idx,
                    1 * nns_agent => request_provider.list_deployed_snses(CallMode::Query),
                    1 * app_agent => request_provider.list_sns_canisters(CallMode::Query),
                    1 * app_agent => request_provider.icrc1_metadata(CallMode::Query),
                    1 * app_agent => request_provider.get_metadata(CallMode::Query),
                    1 * app_agent => request_provider.get_state(CallMode::Query),
                ];
                request_outcome.into_test_outcome()
            }
        }
    };

    // --- Generate workload ---
    let engine = Engine::new(log.clone(), future_generator, rps as f64, duration)
        .increase_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT);

    // --- Emit metrics ---
    let metrics =
        block_on(engine.execute(LoadTestMetrics::new(log), LoadTestMetrics::aggregator_fn))
            .expect("Workload execution has failed.");
    env.emit_report(format!("{metrics}"));
}

pub fn workload_direct_auth(env: TestEnv, rps: usize, duration: Duration) {
    let log = env.logger();

    // --- Create a future generator ---
    let future_generator = {
        let participants: Vec<(CanisterAgent, CanisterAgent)> = {
            let nns_node = env.get_first_healthy_nns_node_snapshot();
            let app_node = env.get_first_healthy_application_node_snapshot();
            SnsSaleParticipants::read_attribute(&env)
                .participants
                .into_iter()
                .map(|p| {
                    block_on(async {
                        let nns_agent =
                            nns_node.build_canister_agent_with_identity(p.clone()).await;
                        let app_agent = app_node.build_canister_agent_with_identity(p).await;
                        (nns_agent, app_agent)
                    })
                })
                .collect()
        };
        let request_provider = {
            let sns_client = SnsClient::read_attribute(&env);
            SnsRequestProvider::from_sns_client(&sns_client)
        };
        move |idx| {
            let participant_data: &(CanisterAgent, CanisterAgent) =
                &participants[idx % participants.len()];
            let (nns_agent, app_agent) = (participant_data.0.clone(), participant_data.1.clone());
            async move {
                let request_outcome = canister_requests![
                    idx,
                    1 * nns_agent => request_provider.list_deployed_snses(CallMode::Query),
                    1 * nns_agent => request_provider.list_deployed_snses(CallMode::Update),
                    1 * app_agent => request_provider.list_sns_canisters(CallMode::Query),
                    1 * app_agent => request_provider.list_sns_canisters(CallMode::Update),
                    1 * app_agent => request_provider.icrc1_metadata(CallMode::Query),
                    1 * app_agent => request_provider.icrc1_metadata(CallMode::Update),
                    1 * app_agent => request_provider.get_metadata(CallMode::Query),
                    1 * app_agent => request_provider.get_metadata(CallMode::Update),
                    1 * app_agent => request_provider.get_state(CallMode::Query),
                    1 * app_agent => request_provider.get_state(CallMode::Update),
                ];
                request_outcome.into_test_outcome()
            }
        }
    };

    // --- Generate workload ---
    let engine = Engine::new(log.clone(), future_generator, rps as f64, duration)
        .increase_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT);

    // --- Emit metrics ---
    let metrics =
        block_on(engine.execute(LoadTestMetrics::new(log), LoadTestMetrics::aggregator_fn))
            .expect("Workload execution has failed.");
    env.emit_report(format!("{metrics}"));
}
