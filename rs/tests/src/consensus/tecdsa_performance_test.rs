use crate::canister_agent::HasCanisterAgentCapability;
use crate::canister_api::{CallMode, Request};
use crate::canister_requests;
use crate::driver::test_env_api::HasPublicApiUrl;
use crate::driver::{
    farm::HostFeature,
    ic::{AmountOfMemoryKiB, ImageSizeGiB, InternetComputer, NrOfVCPUs, Subnet, VmResources},
    prometheus_vm::{HasPrometheus, PrometheusVm},
    test_env::TestEnv,
    test_env_api::{
        HasTopologySnapshot, IcNodeContainer, NnsCanisterWasmStrategy, NnsCustomizations,
    },
};
use crate::generic_workload_engine::engine::Engine;
use crate::generic_workload_engine::metrics::{LoadTestMetricsProvider, RequestOutcome};
use crate::nns_dapp::set_authorized_subnets;
use crate::orchestrator::utils::rw_message::install_nns_with_customizations_and_check_progress;
use crate::orchestrator::utils::subnet_recovery::{
    enable_ecdsa_signing_on_subnet, run_ecdsa_signature_test,
};
use crate::tecdsa::tecdsa_signature_test::{make_key, KEY_ID1};
use crate::util::{block_on, get_app_subnet_and_node, get_nns_node, MessageCanister};

use candid::{Encode, Principal};
use futures::future::join_all;
use ic_config::subnet_config::ECDSA_SIGNATURE_FEE;
use ic_ic00_types::{DerivationPath, Payload, SignWithECDSAArgs, SignWithECDSAReply};
use ic_message::ForwardParams;
use ic_registry_subnet_features::EcdsaConfig;
use ic_registry_subnet_type::SubnetType;
use ic_types::Height;
use slog::info;
use std::time::Duration;
use tokio::runtime::{Builder, Runtime};

// Environment parameters
const NODES_COUNT: usize = 25;
const SUCCESS_THRESHOLD: f64 = 0.33; // If more than 33% of the expected calls are successful the test passes
const REQUESTS_DISPATCH_EXTRA_TIMEOUT: Duration = Duration::from_secs(1);
const TESTING_PERIOD: Duration = Duration::from_secs(900);
const DKG_INTERVAL: u64 = 499;
const MAX_RUNTIME_THREADS: usize = 64;
const MAX_RUNTIME_BLOCKING_THREADS: usize = MAX_RUNTIME_THREADS;

// ECDSA parameters
const QUADRUPLES_TO_CREATE: u32 = 20;
const MAX_QUEUE_SIZE: u32 = 40;
const CANISTER_COUNT: usize = 4;
const SIGNATURE_REQUESTS_PER_SECOND: f64 = 1.9;

pub fn setup(env: TestEnv) {
    PrometheusVm::default()
        .with_required_host_features(vec![HostFeature::Performance])
        .start(&env)
        .expect("Failed to start prometheus VM");

    let vm_resources = VmResources {
        vcpus: Some(NrOfVCPUs::new(64)),
        memory_kibibytes: Some(AmountOfMemoryKiB::new(512_142_680)),
        boot_image_minimal_size_gibibytes: Some(ImageSizeGiB::new(500)),
    };

    InternetComputer::new()
        .with_required_host_features(vec![HostFeature::Performance])
        .add_subnet(
            Subnet::new(SubnetType::System)
                .with_default_vm_resources(vm_resources)
                .add_nodes(1),
        )
        .add_subnet(
            Subnet::new(SubnetType::Application)
                .with_default_vm_resources(vm_resources)
                .with_dkg_interval_length(Height::from(DKG_INTERVAL))
                .with_ecdsa_config(EcdsaConfig {
                    quadruples_to_create_in_advance: QUADRUPLES_TO_CREATE,
                    key_ids: vec![make_key(KEY_ID1)],
                    max_queue_size: Some(MAX_QUEUE_SIZE),
                    signature_request_timeout_ns: None,
                    idkg_key_rotation_period_ms: None,
                })
                .add_nodes(NODES_COUNT),
        )
        .setup_and_start(&env)
        .expect("Failed to setup IC under test");

    install_nns_with_customizations_and_check_progress(
        env.topology_snapshot(),
        NnsCanisterWasmStrategy::TakeBuiltFromSources,
        NnsCustomizations::default(),
    );
    set_authorized_subnets(&env);
    env.sync_prometheus_config_with_topology();
}

#[derive(Clone)]
pub struct EcdsaSignatureRequest {
    pub principal: Principal,
    pub payload: Vec<u8>,
}

impl EcdsaSignatureRequest {
    pub fn new(principal: Principal, key_id: &str) -> Self {
        let message_hash = [1; 32];
        let signature_request = SignWithECDSAArgs {
            message_hash,
            derivation_path: DerivationPath::new(Vec::new()),
            key_id: make_key(key_id),
        };
        let signature_payload = Encode!(&signature_request).unwrap();

        let params = ForwardParams {
            receiver: Principal::management_canister(),
            method: "sign_with_ecdsa".to_string(),
            cycles: ECDSA_SIGNATURE_FEE.get() * 2,
            payload: signature_payload,
        };
        let payload = Encode!(&params).unwrap();

        Self { principal, payload }
    }
}

impl Request<SignWithECDSAReply> for EcdsaSignatureRequest {
    fn mode(&self) -> CallMode {
        CallMode::Update
    }
    fn canister_id(&self) -> Principal {
        self.principal
    }
    fn method_name(&self) -> String {
        "forward".to_string()
    }
    fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }
    fn parse_response(&self, raw_response: &[u8]) -> anyhow::Result<SignWithECDSAReply> {
        Ok(SignWithECDSAReply::decode(raw_response)?)
    }
}

pub fn test(env: TestEnv) {
    let log = env.logger();

    let duration: Duration = TESTING_PERIOD;
    let rps = SIGNATURE_REQUESTS_PER_SECOND;

    let topology_snapshot = env.topology_snapshot();
    let nns_node = get_nns_node(&topology_snapshot);
    let nns_agent = nns_node.with_default_agent(|agent| async move { agent });
    let nns_canister = block_on(MessageCanister::new(
        &nns_agent,
        nns_node.effective_canister_id(),
    ));

    let (app_subnet, app_node) = get_app_subnet_and_node(&topology_snapshot);
    let app_agent = app_node.with_default_agent(|agent| async move { agent });

    info!(log, "Step 1: Enabling tECDSA signing and ensuring it works");
    let key = enable_ecdsa_signing_on_subnet(&nns_node, &nns_canister, app_subnet.subnet_id, &log);
    run_ecdsa_signature_test(&nns_canister, &log, key);

    let requests = (0..CANISTER_COUNT)
        .map(|_| {
            let principal = block_on(MessageCanister::new_with_cycles(
                &app_agent,
                app_node.effective_canister_id(),
                u128::MAX,
            ))
            .canister_id();
            EcdsaSignatureRequest::new(principal, KEY_ID1)
        })
        .collect::<Vec<_>>();

    // create the runtime that lives until this variable is dropped.
    info!(
        env.logger(),
        "Step 2: Start tokio runtime: worker_threads={}, blocking_threads={}",
        MAX_RUNTIME_THREADS,
        MAX_RUNTIME_BLOCKING_THREADS
    );
    let rt: Runtime = Builder::new_multi_thread()
        .worker_threads(MAX_RUNTIME_THREADS)
        .max_blocking_threads(MAX_RUNTIME_BLOCKING_THREADS)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async move {
        let agents = join_all(
            app_subnet
                .nodes()
                .map(|n| async move { n.build_canister_agent().await }),
        )
        .await;

        info!(log, "Step 3: Instantiate and start the workload generator");
        let generator = move |idx: usize| {
            let request = requests[idx % requests.len()].clone();
            let agent = agents[idx % agents.len()].clone();
            async move {
                let request_outcome = canister_requests![
                    idx,
                    1 * agent => request,
                ];
                request_outcome.into_test_outcome()
            }
        };

        let metrics = Engine::new(log.clone(), generator, rps, duration)
            .increase_dispatch_timeout(REQUESTS_DISPATCH_EXTRA_TIMEOUT)
            .execute_simply(log.clone())
            .await;

        info!(log, "Reporting workload execution results");
        env.emit_report(format!("{}", metrics));
        info!(log, "Step 4: Assert expected number of successful requests");
        let requests_count = rps * duration.as_secs_f64();
        let min_expected_success_calls = (SUCCESS_THRESHOLD * requests_count) as usize;
        info!(
            log,
            "Minimal expected number of success calls {}", min_expected_success_calls,
        );
        info!(
            log,
            "Number of success calls {}, failure calls {}",
            metrics.success_calls(),
            metrics.failure_calls()
        );
        assert!(metrics.success_calls() >= min_expected_success_calls);
    });
}
