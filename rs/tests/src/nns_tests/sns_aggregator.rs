use std::time::{Duration, Instant};

use crate::{
    driver::test_env_api::retry_async,
    workload::{CallSpec, Request, RoundRobinPlan, Workload},
};
use anyhow::{bail, Context};
use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::Agent;
use ic_icrc1_agent::CallMode;
use ic_registry_subnet_type::SubnetType;
use ic_sns_swap::pb::v1::{GetStateResponse, Params};
use ic_utils::{
    call::SyncCall,
    interfaces::{http_request::HttpResponse, HttpRequestCanister, ManagementCanister},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use slog::{info, Logger};

use crate::{
    driver::{
        ic::InternetComputer,
        test_env::{TestEnv, TestEnvAttribute},
        test_env_api::{
            GetFirstHealthyNodeSnapshot, HasDependencies, HasGroupSetup, HasPublicApiUrl,
            HasTopologySnapshot, HasWasm, IcNodeContainer,
        },
    },
    util::{block_on, delay},
};

use super::sns_deployment::{
    self, install_nns, install_sns, HasSnsAgentCapability, SaleParticipant, SnsClient,
    SnsRequestProvider,
};

use ic_base_types::PrincipalId;

use anyhow::Result;

// Taken from https://github.com/dfinity/nns-dapp/blob/main/frontend/src/lib/constants/sns.constants.ts
const AGGREGATOR_CANISTER_PATH: &str = "/sns/list/latest/slow.json";
const AGGREGATOR_CANISTER_VERSION: &str = "v1";

// Using the current workload generator to measure update call durations e2e requires setting this to "infinity"
// as we should never stop awaiting the execution completion (unless the overall workload timeout controlled
// by `RESPONSES_COLLECTION_EXTRA_TIMEOUT` is reached).
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(1_000);
const RESPONSES_COLLECTION_EXTRA_TIMEOUT: Duration = Duration::from_secs(5);

fn config_for_security_testing(env: &TestEnv) {
    env.ensure_group_setup_created();
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
    install_nns(env, None);
    install_sns(env);
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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl AggregatorClient {
    fn id(canister: &HttpRequestCanister) -> PrincipalId {
        PrincipalId(*canister.canister_id_())
    }

    pub fn principal(&self) -> Principal {
        Principal::try_from(self.canister_id).unwrap()
    }

    pub fn aggregator_http_endpoint() -> String {
        format!("/{AGGREGATOR_CANISTER_VERSION}{AGGREGATOR_CANISTER_PATH}")
    }

    async fn http_get_request<'agent>(
        log: &Logger,
        canister: &HttpRequestCanister<'agent>,
        relative_url: String,
    ) -> Result<HttpResponse> {
        let (response,) = canister
            .http_request("GET", relative_url.clone(), vec![], vec![])
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

    pub async fn http_get_favicon<'agent>(
        log: &Logger,
        canister: &HttpRequestCanister<'agent>,
    ) -> Result<Vec<u8>> {
        let url = "/favicon.ico".to_string();
        Self::http_get_request(log, canister, url)
            .await
            .map(|res| res.body)
    }

    pub async fn http_get_asset<'agent>(
        log: &Logger,
        canister: &HttpRequestCanister<'agent>,
    ) -> Result<Vec<u8>> {
        let url = Self::aggregator_http_endpoint();
        Self::http_get_request(log, canister, url)
            .await
            .map(|res| res.body)
    }

    pub async fn extract_first_sns_sale_config<'agent>(
        log: &Logger,
        canister: &HttpRequestCanister<'agent>,
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

    async fn sub_asset<'agent, P>(
        log: &Logger,
        canister: &HttpRequestCanister<'agent>,
        extract_sub_asset: P,
        timeout: Duration,
    ) -> Result<Value>
    where
        P: Fn(Value) -> Result<Value>,
    {
        retry_async(log, timeout, Duration::from_secs(5), || async {
            let asset_bytes = Self::http_get_asset(log, canister).await?;
            info!(&log, "Try parsing the response body ...");
            let asset: Value = serde_json::from_slice(asset_bytes.as_slice())?;
            extract_sub_asset(asset)
        })
        .await
    }

    pub async fn first_sns_asset<'agent>(
        log: &Logger,
        canister: &HttpRequestCanister<'agent>,
        timeout: Duration,
    ) -> Result<Value> {
        let extract_sub_asset = move |asset| {
            let sub_asset = walk_array(asset, 0)?;
            Ok(sub_asset)
        };
        Self::sub_asset(log, canister, extract_sub_asset, timeout).await
    }

    pub async fn first_swap_params<'agent>(
        log: &Logger,
        canister: &HttpRequestCanister<'agent>,
        timeout: Duration,
    ) -> Result<Value> {
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
        Self::sub_asset(log, canister, extract_sub_asset, timeout).await
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
            let p = env.get_dependency_path("external/sns_aggregator/file/sns_aggregator.wasm");
            let p = std::fs::canonicalize(p.clone())
                .unwrap_or_else(|e| panic!("cannot obtain canonical path from {p:?}: {e:?}"));
            let canister_bytes = env.load_wasm(p);
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
                        .call_and_wait(delay())
                        .await
                        .unwrap();
                    info!(
                        log,
                        "Successfully created canister {canister_id:?} using provisional builder"
                    );
                    management_canister
                        .install_code(&canister_id, &canister_bytes)
                        .call_and_wait(delay())
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

    info!(log, "Fetch SNS sale params from aggregator canister ...");
    let sns_sale_params_from_aggregator = {
        let aggregator = AggregatorClient::read_attribute(&env);
        let agent = app_node.build_default_agent();
        let http_canister = aggregator.new_http_canister(&agent);
        let swap_params = block_on(AggregatorClient::first_swap_params(
            &log,
            &http_canister,
            Duration::from_secs(2 * 60),
        ))
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
        let sns_client = SnsClient::read_attribute(&env);
        let sns_agent = app_node.build_sns_agent();
        let request_provider = SnsRequestProvider::from_sns_client(&sns_client);
        let request = request_provider.get_state(CallMode::Update);
        let res = block_on(sns_agent.update(request)).unwrap();
        let res = Decode!(res.as_slice(), GetStateResponse).expect("failed to decode");
        // We've already checked above that the SNS sale params had propagated through the aggregator canister.
        // Thus, they must also be availabe while querying the SNS directly.
        let sns_sale_params = res.swap.unwrap().params.unwrap();
        let sns_sale_params_json = serde_json::to_value(sns_sale_params.clone()).unwrap();
        info!(
            log,
            "Obtained SNS sale parameters from SNS sale canister: {sns_sale_params_json:#}"
        );
        sns_sale_params
    };
    assert_eq!(sns_sale_params_from_aggregator, sns_sale_params_from_sns);
    info!(
        log,
        "========== The SNS Aggregator has detected an SNS token sale in {:?} ===========",
        start_time.elapsed()
    );
}

pub fn workload_via_aggregator(env: TestEnv, rps: usize, duration: Duration) {
    let log = env.logger();

    // --- Create a plan ---
    let plan = {
        #[derive(Debug, Clone, Serialize, Deserialize, CandidType)]
        struct SimpleHttpHeader(String, String);

        #[derive(Debug, Clone, Serialize, Deserialize, CandidType)]
        struct SimpleHttpRequest {
            url: String,
            method: String,
            headers: Vec<SimpleHttpHeader>,
            body: Vec<u8>,
        }
        let http_request = SimpleHttpRequest {
            url: AggregatorClient::aggregator_http_endpoint(),
            method: "GET".to_string(),
            headers: vec![],
            body: vec![],
        };
        let payload = Encode!(&http_request).unwrap();
        let aggregator = AggregatorClient::read_attribute(&env);
        let request = Request::Query(CallSpec::new(
            aggregator.principal(),
            "http_request",
            payload,
        ));
        RoundRobinPlan::new(vec![request])
    };

    // --- Generate workload ---
    let workload = {
        let app_node = env.get_first_healthy_application_node_snapshot();
        let agent = app_node.build_default_agent();
        Workload::new(vec![agent], rps, duration, plan, log.clone())
            .with_responses_collection_extra_timeout(RESPONSES_COLLECTION_EXTRA_TIMEOUT)
            .increase_requests_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT)
    };

    // --- Emit metrics ---
    let metrics = block_on(workload.execute()).expect("Workload execution has failed.");
    env.emit_report(format!("{metrics}"));
}

pub fn workload_direct(env: TestEnv, rps: usize, duration: Duration) {
    let log = env.logger();

    // --- Create a plan ---
    let sns_client = SnsClient::read_attribute(&env);
    let request_provider = SnsRequestProvider::from_sns_client(&sns_client);
    let plan = RoundRobinPlan::new(vec![
        request_provider.list_deployed_snses(CallMode::Query),
        request_provider.list_sns_canisters(CallMode::Query),
        request_provider.icrc1_metadata(CallMode::Query),
        request_provider.get_metadata(CallMode::Query),
        request_provider.get_state(CallMode::Query),
    ]);

    // --- Generate workload ---
    let workload = {
        let app_agent = {
            let app_node = env.get_first_healthy_application_node_snapshot();
            app_node.build_default_agent()
        };
        let nns_agent = {
            let nns_node = env.get_first_healthy_nns_node_snapshot();
            nns_node.build_default_agent()
        };
        // Note: the workload generator is designed for single-subnet applications.
        // However, here we abuse its ability to rotate multiple agents to establish
        // a combined workload for the NNS and the applciations subnets. The agent
        // rotation is synchronized with the plan requests (see `plan` above).
        // Thus, the `list_deployed_snses` request will always be executed by the
        // `nns_agent`, while the other requests will always be executed by the `app_agent`.
        let agents = vec![
            nns_agent, // for list_deployed_snses
            app_agent.clone(),
            app_agent.clone(),
            app_agent.clone(),
            app_agent,
        ];
        Workload::new(agents, rps, duration, plan, log.clone())
            .with_responses_collection_extra_timeout(RESPONSES_COLLECTION_EXTRA_TIMEOUT)
            .increase_requests_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT)
    };

    // --- Emit metrics ---
    let metrics = block_on(workload.execute()).expect("Workload execution has failed.");
    env.emit_report(format!("{metrics}"));
}

pub fn workload_direct_auth(env: TestEnv, rps: usize, duration: Duration) {
    let log = env.logger();

    // --- Create a plan ---
    let sns_client = SnsClient::read_attribute(&env);
    let request_provider = SnsRequestProvider::from_sns_client(&sns_client);
    let requests = vec![
        request_provider.list_deployed_snses(CallMode::Query),
        request_provider.list_deployed_snses(CallMode::Update),
        request_provider.list_sns_canisters(CallMode::Query),
        request_provider.list_sns_canisters(CallMode::Update),
        request_provider.icrc1_metadata(CallMode::Query),
        request_provider.icrc1_metadata(CallMode::Update),
        request_provider.get_metadata(CallMode::Query),
        request_provider.get_metadata(CallMode::Update),
        request_provider.get_state(CallMode::Query),
        request_provider.get_state(CallMode::Update),
    ];
    let plan = RoundRobinPlan::new(requests.clone());

    // --- Generate workload ---
    let workload = {
        let participants = Vec::<SaleParticipant>::read_attribute(&env);
        let app_node = env.get_first_healthy_application_node_snapshot();
        let nns_node = env.get_first_healthy_nns_node_snapshot();
        let mut agents = vec![];
        for participant in participants {
            for request in &requests[..] {
                // Note: the workload generator is designed for single-subnet applications.
                // However, here we abuse its ability to rotate multiple agents to establish
                // a combined workload for the NNS and the applciations subnets. The agent
                // rotation is synchronized with the plan requests (see `plan` above).
                // Thus, the `list_deployed_snses` request will always be executed by the
                // `nns_agent`, while the other requests will always be executed by the `app_agent`.
                let agent = if request.spec().method_name == "list_deployed_snses" {
                    nns_node.build_sns_agent_with_identity(participant.clone())
                } else {
                    app_node.build_sns_agent_with_identity(participant.clone())
                };
                agents.push(agent.get());
            }
        }
        Workload::new(agents, rps, duration, plan, log.clone())
            .with_responses_collection_extra_timeout(RESPONSES_COLLECTION_EXTRA_TIMEOUT)
            .increase_requests_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT)
    };

    // --- Emit metrics ---
    let metrics = block_on(workload.execute()).expect("Workload execution has failed.");
    env.emit_report(format!("{metrics}"));
}
