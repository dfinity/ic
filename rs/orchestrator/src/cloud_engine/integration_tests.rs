//! Covers the orchestrator (CloudEngineManager) and tests that `ic-gateway`
//! is started with the right configuration coming from the two cloud engine
//! canisters (engine management canister and operator canister).
//!
//! The engine management canister and the operator are both
//! `//rs/rust_canisters/cloud_engine_mock` on PocketIC, and `ic-gateway` is a
//! stub that dumps its environment, so the assertions are on what a real
//! process was handed.
//!
//! Not covered: the API boundary node the management canister lookup goes
//! through in production.

use super::{config::EngineConfig, *};
use crate::{
    processes::{IcGatewayProcessConfig, MultipleProcessesManager, ReplicaProcessConfig},
    registry_helper::RegistryHelper,
};
use assert_matches::assert_matches;
use candid::{CandidType, Encode, Principal};
use ic_agent::Agent;
use ic_crypto_temp_crypto::{NodeKeysToGenerate, TempCryptoComponent};
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use ic_interfaces_registry::RegistryClient;
use ic_logger::no_op_logger;
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::subnet::v1::{SubnetRecord, SubnetType as PbSubnetType};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::{ROOT_SUBNET_ID_KEY, make_subnet_record_key};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_test_utilities_registry::add_subnet_key_record;
use ic_test_utilities_types::ids::{NODE_1, SUBNET_1, SUBNET_2};
use ic_types::{PlatformVersion, ReplicaVersion, subnet_id_into_protobuf};
use nix::unistd::Pid;
use pocket_ic::{PocketIcBuilder, nonblocking::PocketIc};
use std::{
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;

const VERSION: RegistryVersion = RegistryVersion::new(1);
const ENGINE_SUBNET: SubnetId = SUBNET_1;
const ROOT_SUBNET: SubnetId = SUBNET_2;

const REPLICA_VERSION: &str = "replica_version_0.1";
const BASE_DOMAIN: &str = "engine.example.com";
const OTHER_BASE_DOMAIN: &str = "renamed.example.com";
const DNS_API_URL: &str = "https://dns1.example.com/";
const DNS_API_KEY: &str = "dns-api-key";
const ACME_ID: &str = "https://acme.example.com/acct/1";
const ACME_KEY_PKCS8: &str = "a2V5";
const ACME_DIRECTORY: &str = "https://acme.example.com/directory";

/// Mirrors the operator's reply.
#[derive(CandidType)]
struct HttpGatewayConfigArg {
    base_domains: Option<Vec<String>>,
    dns_api_urls: Option<Vec<String>>,
    dns_api_key: Option<String>,
}

#[derive(CandidType)]
struct AcmeCredentialsArg {
    id: Option<String>,
    key_pkcs8: Option<String>,
    directory: Option<String>,
}

fn complete_config() -> HttpGatewayConfigArg {
    HttpGatewayConfigArg {
        base_domains: Some(vec![BASE_DOMAIN.to_string()]),
        dns_api_urls: Some(vec![DNS_API_URL.to_string()]),
        dns_api_key: Some(DNS_API_KEY.to_string()),
    }
}

fn complete_acme_credentials() -> AcmeCredentialsArg {
    AcmeCredentialsArg {
        id: Some(ACME_ID.to_string()),
        key_pkcs8: Some(ACME_KEY_PKCS8.to_string()),
        directory: Some(ACME_DIRECTORY.to_string()),
    }
}

struct Fixture {
    pocket_ic: PocketIc,
    operator: Principal,
    manager: CloudEngineManager,
    processes: MultipleProcessesManager,
    metrics: Arc<OrchestratorMetrics>,
    engine_config: Arc<RwLock<Option<EngineConfig>>>,
    /// Where the `ic-gateway` stub dumps its environment.
    env_dump: PathBuf,
    acme_cache_dir: PathBuf,
    _dir: TempDir,
}

/// A node that knows nothing yet: it has to find its operator before it can
/// read anything off it.
///
/// `None` when there is nothing to run against, which is how these tests skip
/// under `cargo test`.
async fn setup() -> Option<Fixture> {
    let (Some(_), Some(operator_wasm)) = (
        std::env::var("POCKET_IC_BIN").ok(),
        std::env::var("CLOUD_ENGINE_MOCK_WASM").ok(),
    ) else {
        eprintln!(
            "skipped: PocketIC and the mock operator wasm need to be provided as ENV variables"
        );
        return None;
    };
    let operator_wasm = std::fs::read(&operator_wasm)
        .unwrap_or_else(|err| panic!("cannot read {operator_wasm}: {err}"));

    let mut pocket_ic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_application_subnet()
        .build_async()
        .await;
    // The CloudEngineManager addresses the local replica, so we point it
    // directly to PocketIC
    let replica_url = pocket_ic.make_live(None).await;
    let replica_addr = SocketAddr::from((
        [127, 0, 0, 1],
        replica_url.port().expect("a live PocketIC URL has a port"),
    ));
    let root_key = pocket_ic
        .root_key()
        .await
        .expect("the NNS subnet provides a root key");

    // Any subnet works: what makes this a cloud engine is the subnet record
    // in the registry below, which is what the orchestrator looks at.
    let app_subnet = pocket_ic.topology().await.get_app_subnets()[0];
    // Install the engine management and engine operator canister
    let management = setup_canister(&pocket_ic, app_subnet, &operator_wasm).await;
    let operator = setup_canister(&pocket_ic, app_subnet, &operator_wasm).await;
    update(
        &pocket_ic,
        management,
        "set_engine_operator",
        Encode!(&ENGINE_SUBNET.get().0, &operator).unwrap(),
    )
    .await;

    let (registry, registry_client) = registry_for_test(&root_key);
    let crypto = Arc::new(
        TempCryptoComponent::builder()
            .with_registry(registry_client)
            .with_node_id(NODE_1)
            .with_keys(NodeKeysToGenerate::only_node_signing_key())
            .build(),
    );

    let dir = tempfile::tempdir().unwrap();
    let env_dump = dir.path().join("ic-gateway.env.dump");
    let acme_cache_dir = dir.path().join("acme");
    write_stub(&dir.path().join("ic-gateway"), Some(&env_dump));
    write_stub(&dir.path().join("replica"), None);
    let env_file = dir.path().join("ic-gateway.env");
    std::fs::write(&env_file, b"LISTEN_PLAIN=[::]:80\n").unwrap();

    let metrics = Arc::new(OrchestratorMetrics::new(&MetricsRegistry::new()));
    let engine_config = Arc::new(RwLock::new(None));

    let mut manager = CloudEngineManager::new(
        Arc::clone(&registry),
        Arc::new(RwLock::new(SubnetAssignment::Assigned(ENGINE_SUBNET))),
        crypto,
        Some(CanisterId::unchecked_from_principal(management.into())),
        replica_addr,
        Arc::clone(&engine_config),
        Arc::clone(&metrics),
        no_op_logger(),
    )
    .expect("the manager should be constructible");
    manager
        .discovery
        .use_agent(anonymous_agent(replica_url, &root_key));

    let processes = MultipleProcessesManager::new(
        ReplicaProcessConfig {
            ic_binary_dir: dir.path().to_path_buf(),
            cup_path: dir.path().join("cup.types.v1.CatchUpPackage.pb"),
            replica_config_file: dir.path().join("ic.json5"),
        },
        IcGatewayProcessConfig {
            ic_binary_dir: dir.path().to_path_buf(),
            ic_gateway_env_file: env_file,
            acme_cache_dir: acme_cache_dir.clone(),
        },
        Arc::clone(&engine_config),
        Arc::clone(&registry),
        Arc::clone(&metrics),
        no_op_logger(),
    );

    Some(Fixture {
        pocket_ic,
        operator,
        manager,
        processes,
        metrics,
        engine_config,
        env_dump,
        acme_cache_dir,
        _dir: dir,
    })
}

async fn setup_canister(pocket_ic: &PocketIc, subnet: Principal, wasm: &[u8]) -> Principal {
    let canister = pocket_ic
        .create_canister_on_subnet(None, None, subnet)
        .await;
    pocket_ic.add_cycles(canister, 100_000_000_000_000).await;
    pocket_ic
        .install_canister(canister, wasm.to_vec(), vec![], None)
        .await;

    canister
}

async fn update(pocket_ic: &PocketIc, canister: Principal, method: &str, arg: Vec<u8>) {
    pocket_ic
        .update_call(canister, Principal::anonymous(), method, arg)
        .await
        .unwrap_or_else(|err| panic!("{method} failed: {err:?}"));
}

/// Replacement agent for the CloudEngineManager to bypass the API BNs.
fn anonymous_agent(url: Url, root_key: &[u8]) -> Agent {
    let agent = Agent::builder()
        .with_url(url)
        .with_verify_query_signatures(true)
        .build()
        .expect("the agent should be buildable");
    agent.set_root_key(root_key.to_vec());

    agent
}

/// Orchestrator uses this registry to get:
/// * the root key of the PocketIC instance
/// * the type of the subnet it is part of (CloudEngine)
fn registry_for_test(root_key_der: &[u8]) -> (Arc<RegistryHelper>, Arc<dyn RegistryClient>) {
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());

    let root_key = parse_threshold_sig_key_from_der(root_key_der)
        .expect("PocketIC's root key is a BLS12-381 key in DER");
    add_subnet_key_record(&data_provider, VERSION.get(), ROOT_SUBNET, root_key);
    data_provider
        .add(
            ROOT_SUBNET_ID_KEY,
            VERSION,
            Some(subnet_id_into_protobuf(ROOT_SUBNET)),
        )
        .unwrap();
    data_provider
        .add(
            &make_subnet_record_key(ENGINE_SUBNET),
            VERSION,
            Some(SubnetRecord {
                subnet_type: PbSubnetType::CloudEngine as i32,
                ..Default::default()
            }),
        )
        .unwrap();

    let registry_client = Arc::new(FakeRegistryClient::new(data_provider));
    registry_client.update_to_latest_version();

    (
        Arc::new(RegistryHelper::new(
            NODE_1,
            Arc::clone(&registry_client) as Arc<dyn RegistryClient>,
            no_op_logger(),
        )),
        registry_client,
    )
}

/// Creates a stub process that dumps its environment where the test can read
/// it, then stays alive so the process manager sees it running.
fn write_stub(path: &Path, env_dump: Option<&Path>) {
    let script = match env_dump {
        Some(dump) => format!("#!/bin/sh\nenv > {}\nexec sleep 300\n", dump.display()),
        None => "#!/bin/sh\nexec sleep 300\n".to_string(),
    };
    std::fs::write(path, script).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

impl Fixture {
    /// An engine whose operator serves everything `ic-gateway` needs.
    async fn configure_engine(&self) {
        self.set_config(complete_config()).await;
        self.set_acme_credentials(complete_acme_credentials()).await;
    }

    async fn set_config(&self, config: HttpGatewayConfigArg) {
        self.call_operator("set_config", Encode!(&config).unwrap())
            .await;
    }

    async fn set_acme_credentials(&self, acme: AcmeCredentialsArg) {
        self.call_operator("set_acme_credentials", Encode!(&acme).unwrap())
            .await;
    }

    async fn set_unauthorized(&self, unauthorized: bool) {
        self.call_operator("set_unauthorized", Encode!(&unauthorized).unwrap())
            .await;
    }

    async fn call_operator(&self, method: &str, arg: Vec<u8>) {
        update(&self.pocket_ic, self.operator, method, arg).await;
    }

    /// One turn of the process manager.
    fn start_all(&mut self) {
        self.processes
            .start_all(
                PlatformVersion {
                    guestos_version: ReplicaVersion::try_from(REPLICA_VERSION).unwrap(),
                    replica_version: ReplicaVersion::try_from(REPLICA_VERSION).unwrap(),
                },
                ENGINE_SUBNET,
                VERSION,
            )
            .expect("starting the managed processes should not fail");
    }

    /// A restart takes two turns, one to signal the old process and one to
    /// start the new, so drive it until the dump shows `domain`. Gives up
    /// after five seconds.
    async fn await_gateway_serving(&mut self, domain: &str) {
        for _ in 0..50 {
            self.start_all();
            if self
                .gateway_env()
                .is_some_and(|env| env.contains(&format!("DOMAIN={domain}")))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!(
            "ic-gateway was never started with DOMAIN={domain}; last dump: {:?}",
            self.gateway_env()
        );
    }

    fn gateway_env(&self) -> Option<String> {
        std::fs::read_to_string(&self.env_dump).ok()
    }

    fn gateway_pid(&self) -> Option<Pid> {
        self.processes.get_ic_gateway_pid()
    }

    /// What the manager published for the process manager to run with.
    fn published_config(&self) -> Option<EngineConfig> {
        self.engine_config.read().unwrap().clone()
    }

    fn fetches(&self, outcome: &str) -> u64 {
        self.metrics
            .cloud_engine_config_fetches
            .with_label_values(&[outcome])
            .get()
    }

    fn last_success(&self) -> i64 {
        self.metrics.cloud_engine_config_last_success.get()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_operators_configuration_reaches_ic_gateway() {
    let Some(mut fixture) = setup().await else {
        return;
    };
    fixture.configure_engine().await;

    fixture.manager.check().await;

    assert_eq!(fixture.fetches(OUTCOME_OK), 1);
    assert!(fixture.last_success() > 0);

    fixture.await_gateway_serving(BASE_DOMAIN).await;

    let env = fixture
        .gateway_env()
        .expect("the stub dumped its environment");
    // The engine's own values, under the names `ic-gateway` expects.
    assert!(env.contains(&format!("DOMAIN={BASE_DOMAIN}")), "{env}");
    assert!(
        env.contains(&format!("ACME_DNS_IC_DNS_LB_URLS={DNS_API_URL}")),
        "{env}"
    );
    assert!(
        env.contains(&format!("ACME_DNS_IC_DNS_LB_TOKEN={DNS_API_KEY}")),
        "{env}"
    );
    assert!(
        env.contains(&format!(
            "ACME_CACHE_PATH={}",
            fixture.acme_cache_dir.display()
        )),
        "{env}"
    );
    // `ic-gateway` deserializes this into an `instant_acme` account, so the
    // three fields have to arrive as one JSON object.
    assert!(
        env.contains(&format!(
            r#"ACME_ACCOUNT_CREDS={{"id":"{ACME_ID}","key_pkcs8":"{ACME_KEY_PKCS8}","directory":"{ACME_DIRECTORY}"}}"#
        )),
        "{env}"
    );
    // The shipped file stays the base layer.
    assert!(env.contains("LISTEN_PLAIN=[::]:80"), "{env}");
}

#[tokio::test(flavor = "multi_thread")]
async fn ic_gateway_restarts_only_when_the_configuration_changes() {
    let Some(mut fixture) = setup().await else {
        return;
    };
    fixture.configure_engine().await;
    fixture.manager.check().await;
    fixture.await_gateway_serving(BASE_DOMAIN).await;
    let pid = fixture.gateway_pid().expect("ic-gateway should be running");

    // The configuration is re-read every 10 seconds, and an unchanged one has
    // to leave the process alone: a restart drops every connection the engine
    // serves.
    fixture.manager.check().await;
    fixture.start_all();

    assert_eq!(fixture.fetches(OUTCOME_OK), 2);
    assert_eq!(fixture.gateway_pid(), Some(pid));

    fixture
        .set_config(HttpGatewayConfigArg {
            base_domains: Some(vec![OTHER_BASE_DOMAIN.to_string()]),
            ..complete_config()
        })
        .await;
    fixture.manager.check().await;

    // The process runner only compares versions, so an environment-only change
    // takes effect through the explicit restart.
    fixture.await_gateway_serving(OTHER_BASE_DOMAIN).await;

    assert_ne!(fixture.gateway_pid(), Some(pid));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_incomplete_configuration_leaves_ic_gateway_down() {
    let Some(mut fixture) = setup().await else {
        return;
    };
    // The engine has domains but no DNS API yet.
    fixture
        .set_config(HttpGatewayConfigArg {
            dns_api_urls: None,
            ..complete_config()
        })
        .await;
    fixture
        .set_acme_credentials(complete_acme_credentials())
        .await;

    fixture.manager.check().await;
    fixture.start_all();

    assert_eq!(fixture.fetches(OUTCOME_INCOMPLETE), 1);
    assert_eq!(fixture.published_config(), None);
    assert!(!fixture.processes.is_ic_gateway_running());
    assert_eq!(fixture.gateway_env(), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_management_canister_names_the_operator() {
    let Some(mut fixture) = setup().await else {
        return;
    };

    let operator = fixture
        .manager
        .discovery
        .resolve(ENGINE_SUBNET, VERSION)
        .await
        .expect("the management canister should name an operator");

    assert_eq!(operator.get().0, fixture.operator);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_subnet_without_an_operator_is_a_failure() {
    let Some(mut fixture) = setup().await else {
        return;
    };

    // An engine the management canister has not been told about.
    let err = fixture
        .manager
        .discovery
        .resolve(ROOT_SUBNET, VERSION)
        .await
        .expect_err("an engine with no operator on file cannot resolve one");

    assert_matches!(err, CloudEngineError::Failed(msg) if msg.contains("does not know an operator"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_operator_that_does_not_recognize_this_node_is_not_ready() {
    let Some(mut fixture) = setup().await else {
        return;
    };
    fixture.configure_engine().await;
    fixture.set_unauthorized(true).await;

    let err = fixture
        .manager
        .fetch(ENGINE_SUBNET, VERSION)
        .await
        .expect_err("an operator that rejects this node cannot be read");

    // Not a failure: the operator is ours, it has just not seen this node yet.
    assert_matches!(err, CloudEngineError::NotReady);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_operator_that_stays_unauthorized_is_resolved_again() {
    let Some(mut fixture) = setup().await else {
        return;
    };
    fixture.configure_engine().await;
    fixture.set_unauthorized(true).await;

    fixture.manager.check().await;

    // Expected right after an operator install: nothing to apply, not an
    // error, and the operator is kept.
    assert_eq!(fixture.fetches(OUTCOME_NOT_READY), 1);
    assert_eq!(fixture.fetches(OUTCOME_ERROR), 0);
    assert_eq!(fixture.published_config(), None);
    assert!(fixture.manager.discovery.remembered().is_some());

    for _ in 1..MAX_CONSECUTIVE_NOT_READY {
        fixture.manager.check().await;
    }

    // An operator that never recognizes this node may be the wrong one, so it
    // is dropped and looked up again.
    assert_eq!(fixture.manager.discovery.remembered(), None);
    assert_eq!(
        fixture.fetches(OUTCOME_NOT_READY),
        MAX_CONSECUTIVE_NOT_READY as u64
    );

    fixture.set_unauthorized(false).await;
    fixture.manager.check().await;

    // Resolving a second time got us back to the same operator, which now
    // answers, so the engine recovers on its own.
    assert_eq!(fixture.fetches(OUTCOME_OK), 1);
    assert!(fixture.published_config().is_some());
}
