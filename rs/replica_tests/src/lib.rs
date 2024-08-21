use core::future::Future;
use ic_base_types::{PrincipalId, SubnetId};
use ic_canister_client_sender::Sender;
use ic_config::{crypto::CryptoConfig, transport::TransportConfig, Config};
use ic_error_types::{ErrorCode, RejectCode, UserError};
use ic_execution_environment::IngressHistoryReaderImpl;
use ic_interfaces::execution_environment::{
    IngressHistoryReader, QueryExecutionError, QueryExecutionService,
};
use ic_interfaces_registry::RegistryClient;
use ic_interfaces_state_manager::StateReader;
use ic_management_canister_types::{
    CanisterIdRecord, CanisterInstallMode, InstallCodeArgs, Method, Payload,
    ProvisionalCreateCanisterWithCyclesArgs, IC_00,
};
use ic_metrics::MetricsRegistry;
use ic_prep_lib::{
    internet_computer::{IcConfig, TopologyConfig},
    node::{NodeConfiguration, NodeIndex, NodeSecretKeyStore},
    subnet_configuration::{SubnetConfig, SubnetRunningState},
};
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::make_subnet_list_record_key;
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_replica::setup::setup_crypto_provider;
use ic_replicated_state::{CanisterState, ReplicatedState};
use ic_state_machine_tests::StateMachine;
use ic_test_utilities::universal_canister::UNIVERSAL_CANISTER_WASM;
use ic_test_utilities_logger::with_test_replica_logger;
use ic_test_utilities_types::{
    ids::{node_test_id, user_anonymous_id},
    messages::SignedIngressBuilder,
};
use ic_types::{
    artifact::UnvalidatedArtifactMutation,
    ingress::{IngressState, IngressStatus, WasmResult},
    messages::{CertificateDelegation, Query, QuerySource, SignedIngress},
    replica_config::NODE_INDEX_DEFAULT,
    time::expiry_time_from_now,
    CanisterId, Height, NodeId, ReplicaVersion, Time,
};
use prost::Message;
use slog_scope::info;
use std::{
    collections::BTreeMap,
    convert::TryFrom,
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    thread,
    thread::sleep,
    time::{Duration, Instant},
};
use tokio::sync::mpsc::UnboundedSender;
use tower::{buffer::Buffer as TowerBuffer, ServiceExt};

const CYCLES_BALANCE: u128 = 1 << 120;

/// Executes an ingress message and blocks till execution finishes.
///
/// Note: To ensure that this function does not block forever (in case of bugs),
/// this function will panic if the process is not finished in some amount of
/// time.
#[allow(clippy::await_holding_lock)]
fn process_ingress(
    ingress_tx: &UnboundedSender<UnvalidatedArtifactMutation<SignedIngress>>,
    ingress_hist_reader: &dyn IngressHistoryReader,
    msg: SignedIngress,
    time_limit: Duration,
) -> Result<WasmResult, UserError> {
    let msg_id = msg.id();
    ingress_tx
        .send(UnvalidatedArtifactMutation::Insert((msg, node_test_id(1))))
        .unwrap();

    let start = Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(5));
        let ingress_result = (ingress_hist_reader.get_latest_status())(&msg_id);
        match ingress_result {
            IngressStatus::Known { state, .. } => match state {
                IngressState::Completed(result) => {
                    // Don't forget! Signal the runtime to stop.
                    return Ok(result);
                }
                IngressState::Failed(error) => {
                    // Don't forget! Signal the runtime to stop.
                    return Err(error);
                }
                IngressState::Done => {
                    return Err(UserError::new(
                        ErrorCode::SubnetOversubscribed,
                        "The call has completed but the reply/reject data has been pruned.",
                    ));
                }
                IngressState::Received | IngressState::Processing => (),
            },
            IngressStatus::Unknown => (),
        }
        if Instant::now().duration_since(start) > time_limit {
            panic!(
                "Ingress message did not finish executing in {} seconds, panicking",
                time_limit.as_secs()
            );
        }

        // Either this requires only few iterations, so waiting a bit is not an
        // issue. Or, it requires a lot of iterations and then we don't want to burn
        // CPU cycles on CI where such loops run in parallel and potentially steal
        // each others CPU time for no good reason.
        sleep(Duration::from_millis(100));
    }
}

/// This function is here to maintain compatibility with existing tests
/// the *_async is strictly more powerful
pub fn simple_canister_test<F, Out>(f: F) -> Out
where
    F: FnOnce(UniversalCanister) -> Out + 'static,
{
    simple_canister_test_async(|universal_canister| async { f(universal_canister) })
}

/// Initializes a "simple" canister test.
///
/// A simple canister test initializes a `UniversalCanister` that can test
/// different functionality without having the implementor write WAT manually.
pub fn simple_canister_test_async<F, Fut, Out>(f: F) -> Out
where
    Fut: Future<Output = Out>,
    F: FnOnce(UniversalCanister) -> Fut + 'static,
{
    canister_test_async(|runtime| async {
        let canister_id = runtime.create_universal_canister();
        let universal_canister = UniversalCanister {
            runtime,
            canister_id,
        };

        f(universal_canister).await
    })
}

/// An Internet Computer test runtime that:
///
/// * provides an environment with a single replica
/// * does not use http connections
///
/// The code of the replica is the real one, only the interface is changed, with
/// function calls instead of http calls.
pub struct LocalTestRuntime {
    pub query_handler:
        tower::buffer::Buffer<QueryExecutionService, (Query, Option<CertificateDelegation>)>,
    pub ingress_sender: UnboundedSender<UnvalidatedArtifactMutation<SignedIngress>>,
    pub ingress_history_reader: Arc<dyn IngressHistoryReader>,
    pub state_reader: Arc<dyn StateReader<State = ReplicatedState>>,
    pub node_id: NodeId,
    pub nonce: Mutex<u64>,
    pub ingress_time_limit: Duration,
    pub registry_data_provider: Arc<ProtoRegistryDataProvider>,
    pub registry_client: Arc<FakeRegistryClient>,
}

/// This function is here to maintain compatibility with existing tests
/// the *_async is strictly more powerful
pub fn canister_test<F, Out>(f: F) -> Out
where
    F: FnOnce(LocalTestRuntime) -> Out + 'static,
{
    canister_test_async(|runtime| async { f(runtime) })
}

pub fn canister_test_async<Fut, F, Out>(test: F) -> Out
where
    Fut: Future<Output = Out>,
    F: FnOnce(LocalTestRuntime) -> Fut + 'static,
{
    let (config, _tmpdir) = Config::temp_config();
    canister_test_with_config_async(config, get_ic_config(), test)
}

pub fn canister_test_with_config<F, Out>(config: Config, f: F) -> Out
where
    F: FnOnce(LocalTestRuntime) -> Out + 'static,
{
    let ic_config = get_ic_config();
    canister_test_with_ic_config(config, ic_config, f)
}

pub fn canister_test_with_ic_config<F, Out>(config: Config, ic_config: IcConfig, f: F) -> Out
where
    F: FnOnce(LocalTestRuntime) -> Out + 'static,
{
    canister_test_with_config_async(config, ic_config, |runtime| async { f(runtime) })
}

pub fn get_ic_config() -> IcConfig {
    let subnet_index = 0;

    // Choose a temporary directory as the working directory for ic-prep.
    use rand::Rng;
    let random_suffix = rand::thread_rng().gen::<usize>();
    let prep_dir = std::env::temp_dir().join(format!("ic_prep_{}", random_suffix));

    // Create the secret key store in a node a sub-directory of the ic-prep.
    let node_sks = prep_dir.join("node_sks");
    let node_sks = NodeSecretKeyStore::new(node_sks).unwrap();

    // We use the `ic-prep` crate to generate the secret key store and registry
    // entries. The topology contains a single node.
    let mut subnet_nodes: BTreeMap<NodeIndex, NodeConfiguration> = BTreeMap::new();
    subnet_nodes.insert(
        NODE_INDEX_DEFAULT,
        NodeConfiguration {
            xnet_api: SocketAddr::from_str("0.0.0.1:0").expect("can't fail"),
            public_api: SocketAddr::from_str("128.0.0.1:1").expect("can't fail"),
            node_operator_principal_id: None,
            secret_key_store: Some(node_sks),
        },
    );

    let mut topology_config: TopologyConfig = TopologyConfig::default();
    topology_config.insert_subnet(
        subnet_index,
        SubnetConfig::new(
            subnet_index,
            subnet_nodes,
            ReplicaVersion::default(),
            None,
            None,
            None,
            None,
            Some(Duration::from_millis(0)), // Notary time out
            Some(Height::from(19)),         // DKG interval length
            None,
            SubnetType::System,
            None,
            None,
            None,
            None,
            None,
            None,
            vec![],
            vec![],
            SubnetRunningState::Active,
            None,
        ),
    );

    let provisional_whitelist = ProvisionalWhitelist::All;

    // The last argument is true, as that is the default case. False is used only
    // for ic-prep when we handle a specific deployment scenario: deploying
    // without assigning nodes to a particular subnet.
    IcConfig::new(
        prep_dir,
        topology_config,
        ReplicaVersion::default(),
        /* generate_subnet_records= */ true,
        /* nns_subnet_id= */ Some(subnet_index),
        /* release_package_url= */ None,
        /* release_package_sha256_hex= */ None,
        /* provisional_whitelist */ Some(provisional_whitelist),
        None,
        None,
        /* ssh_readonly_access_to_unassgined_nodes */ vec![],
    )
}

pub fn canister_test_with_config_async<Fut, F, Out>(
    mut config: Config,
    ic_config: IcConfig,
    test: F,
) -> Out
where
    Fut: Future<Output = Out>,
    F: FnOnce(LocalTestRuntime) -> Fut + 'static,
{
    with_test_replica_logger(|logger| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _rt_guard = rt.enter();

        let metrics_registry = MetricsRegistry::new();

        let init_ic = ic_config.initialize().expect("can't fail");

        let init_subnet = init_ic.initialized_topology.values().next().unwrap();
        let init_node = init_subnet.initialized_nodes.values().next().unwrap();
        let crypto_root = init_node.crypto_path();
        config.crypto = CryptoConfig::new(crypto_root);

        // load the registry file written by ic-prep
        let data_provider =
            ProtoRegistryDataProvider::load_from_file(init_ic.registry_path().as_path());
        let data_provider = Arc::new(data_provider);
        let fake_registry_client = Arc::new(FakeRegistryClient::new(data_provider.clone()));
        fake_registry_client.update_to_latest_version();
        let registry = fake_registry_client.clone() as Arc<dyn RegistryClient + Send + Sync>;
        let crypto = setup_crypto_provider(
            &config.crypto,
            rt.handle().clone(),
            registry.clone(),
            logger.clone(),
            &metrics_registry,
        );
        let node_id = crypto.get_node_id();
        let crypto = Arc::new(crypto);
        let subnet_list_pb = registry
            .get_versioned_value(
                &make_subnet_list_record_key(),
                registry.get_latest_version(),
            )
            .expect("did not find subnet list in registry")
            .value
            .expect("did not find subnet id");
        let subnet_list_record: ic_protobuf::registry::subnet::v1::SubnetListRecord =
            Message::decode(subnet_list_pb.as_slice()).unwrap();
        let subnet_ids: Vec<SubnetId> = subnet_list_record
            .subnets
            .iter()
            .map(|s| SubnetId::new(PrincipalId::try_from(s.clone().as_slice()).unwrap()))
            .collect();
        assert_eq!(subnet_ids.len(), 1);
        let subnet_id = subnet_ids[0];
        config.transport = TransportConfig {
            node_ip: "0.0.0.0".to_string(),
            listening_port: 0,
            send_queue_size: 0,
            ..Default::default()
        };
        let temp_node = node_id;
        let (state_reader, query_handler, ingress_tx, _p2p_thread_joiner, _) =
            ic_replica::setup_ic_stack::construct_ic_stack(
                &logger,
                &metrics_registry,
                &tokio::runtime::Handle::current(),
                &tokio::runtime::Handle::current(),
                &tokio::runtime::Handle::current(),
                &tokio::runtime::Handle::current(),
                config.clone(),
                temp_node,
                subnet_id,
                registry.clone(),
                crypto,
                None,
                ic_tracing::ReloadHandles::new(tracing_subscriber::reload::Layer::new(vec![]).1),
            )
            .expect("Failed to setup p2p");

        let ingress_history_reader =
            IngressHistoryReaderImpl::new(Arc::clone(&state_reader) as Arc<_>);

        std::thread::sleep(std::time::Duration::from_millis(1000));
        // Before height 1 the replica hasn't figured out what
        // the time is. So it's impossible to construct a message
        // with an expiry time that is simultaneously acceptable
        // before height 1 and after height 1 or above.
        //
        // So, loop until we're at height 1 or above.
        while state_reader.get_latest_state().height().get() < 1 {
            // either this requires only few iterations, so
            // waiting a bit is not an issue. Or, it requires
            // a lot of iterations and then we don't want to
            // burn CPU cycles on CI where such loops run in
            // parallel and potentially steal each others CPU
            // time for no good reason.
            thread::sleep(Duration::from_millis(100));
        }

        let runtime = LocalTestRuntime {
            query_handler: tokio::runtime::Handle::current()
                .block_on(async { TowerBuffer::new(query_handler, 1) }),
            ingress_sender: ingress_tx,
            ingress_history_reader: Arc::new(ingress_history_reader),
            state_reader,
            node_id,
            nonce: Mutex::new(0),
            ingress_time_limit: Duration::from_secs(300),
            registry_data_provider: data_provider,
            registry_client: fake_registry_client,
        };
        tokio::runtime::Handle::current().block_on(test(runtime))
    })
}

impl LocalTestRuntime {
    /// This is not a cryptographically secure nonce, rather this is just a
    /// number which is different every time you call this function in a given
    /// canister test
    pub fn get_nonce(&self) -> u64 {
        let mut nonce = self.nonce.lock().unwrap();
        *nonce += 1;
        *nonce
    }

    pub fn upgrade_canister(
        &self,
        canister_id: &CanisterId,
        wat: &str,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.install_canister_helper(InstallCodeArgs::new(
            CanisterInstallMode::Upgrade,
            *canister_id,
            wat::parse_str(wat).expect("couldn't convert wat -> wasm"),
            payload,
            None,
            None,
        ))
    }

    pub fn create_canister(&self) -> Result<CanisterId, UserError> {
        self.create_canister_with_anonymous(self.get_nonce(), CYCLES_BALANCE)
    }

    pub fn create_canister_with_cycles(&self, num_cycles: u128) -> Result<CanisterId, UserError> {
        self.create_canister_with_anonymous(self.get_nonce(), num_cycles)
    }

    pub fn create_canister_with_nonce(&self, nonce: u64) -> Result<CanisterId, UserError> {
        self.create_canister_with_anonymous(nonce, CYCLES_BALANCE)
    }

    pub fn create_canister_with_anonymous(
        &self,
        nonce: u64,
        num_cycles: u128,
    ) -> Result<CanisterId, UserError> {
        let res = process_ingress(
            &self.ingress_sender,
            self.ingress_history_reader.as_ref(),
            SignedIngressBuilder::new()
                .expiry_time(expiry_time_from_now())
                .method_name(Method::ProvisionalCreateCanisterWithCycles)
                .canister_id(IC_00)
                .method_payload(
                    ProvisionalCreateCanisterWithCyclesArgs::new(Some(num_cycles), None).encode(),
                )
                .nonce(nonce)
                .build(),
            self.ingress_time_limit,
        )?;

        let canister_id = match res {
            WasmResult::Reply(reply) => CanisterIdRecord::decode(reply.as_slice())
                .unwrap()
                .get_canister_id(),
            // Got an unexpected result.
            unexpected => panic!("Got unexpected val {:?}", unexpected),
        };

        Ok(canister_id)
    }

    pub fn install_canister(
        &self,
        canister_id: &CanisterId,
        wat: &str,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.install_canister_wasm(
            canister_id,
            wat::parse_str(wat).expect("couldn't convert wat -> wasm"),
            payload,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn install_canister_wasm(
        &self,
        canister_id: &CanisterId,
        wasm: Vec<u8>,
        payload: Vec<u8>,
        compute_allocation: Option<u64>,
        memory_allocation: Option<u64>,
    ) -> Result<WasmResult, UserError> {
        let args = InstallCodeArgs::new(
            CanisterInstallMode::Install,
            *canister_id,
            wasm,
            payload,
            compute_allocation,
            memory_allocation,
        );

        self.install_canister_helper(args)
    }

    /// Create (and install) the universal canister.
    pub fn create_universal_canister(&self) -> CanisterId {
        self.create_universal_canister_with_args(vec![], CYCLES_BALANCE)
    }

    pub fn create_universal_canister_with_args<P: Into<Vec<u8>>>(
        &self,
        payload: P,
        num_cycles: u128,
    ) -> CanisterId {
        let (canister_id, res) = self.create_and_install_canister_wasm(
            UNIVERSAL_CANISTER_WASM.to_vec(),
            payload.into(),
            None,
            None,
            num_cycles,
        );
        res.unwrap();
        canister_id
    }

    pub fn create_and_install_canister(
        &self,
        wat: &str,
        payload: Vec<u8>,
    ) -> (CanisterId, Result<WasmResult, UserError>) {
        let canister_id = self.create_canister().unwrap();
        (
            canister_id,
            self.install_canister(&canister_id, wat, payload),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_and_install_canister_wasm(
        &self,
        wasm: Vec<u8>,
        payload: Vec<u8>,
        compute_allocation: Option<u64>,
        memory_allocation: Option<u64>,
        num_cycles: u128,
    ) -> (CanisterId, Result<WasmResult, UserError>) {
        let canister_id = self.create_canister_with_cycles(num_cycles).unwrap();
        (
            canister_id,
            self.install_canister_wasm(
                &canister_id,
                wasm,
                payload,
                compute_allocation,
                memory_allocation,
            ),
        )
    }

    pub async fn install_canister_helper_async(
        &self,
        install_code_args: InstallCodeArgs,
    ) -> Result<WasmResult, UserError> {
        // Clone data to send to thread
        let ingress_sender = self.ingress_sender.clone();
        let ingress_history_reader = Arc::clone(&self.ingress_history_reader);
        let nonce = self.get_nonce();
        let ingress_time_limit = self.ingress_time_limit;
        // Wrapping the call to process_ingress to avoid blocking current thread

        tokio::runtime::Handle::current()
            .spawn_blocking(move || {
                process_ingress(
                    &ingress_sender,
                    ingress_history_reader.as_ref(),
                    SignedIngressBuilder::new()
                        .expiry_time(expiry_time_from_now())
                        .canister_id(IC_00)
                        .method_name(Method::InstallCode)
                        .method_payload(install_code_args.encode())
                        .nonce(nonce)
                        .build(),
                    ingress_time_limit,
                )
            })
            .await
            .unwrap()
    }

    pub fn install_canister_helper(
        &self,
        install_code_args: InstallCodeArgs,
    ) -> Result<WasmResult, UserError> {
        process_ingress(
            &self.ingress_sender,
            self.ingress_history_reader.as_ref(),
            SignedIngressBuilder::new()
                .expiry_time(expiry_time_from_now())
                .canister_id(IC_00)
                .method_name(Method::InstallCode)
                .method_payload(install_code_args.encode())
                .nonce(self.get_nonce())
                .build(),
            self.ingress_time_limit,
        )
    }

    pub fn canister_state(&self, canister_id: &CanisterId) -> CanisterState {
        self.state_reader
            .get_latest_state()
            .get_ref()
            .canister_state(canister_id)
            .cloned()
            .unwrap()
    }

    pub async fn query<M: Into<String>, P: Into<Vec<u8>>>(
        &self,
        canister_id: CanisterId,
        method_name: M,
        method_payload: P,
    ) -> Result<WasmResult, UserError> {
        let query = Query {
            source: QuerySource::User {
                user_id: user_anonymous_id(),
                ingress_expiry: 0,
                nonce: None,
            },
            receiver: canister_id,
            method_name: method_name.into(),
            method_payload: method_payload.into(),
        };
        let latest = self.state_reader.latest_state_height();
        while self.state_reader.latest_certified_height() < latest {
            thread::sleep(Duration::from_millis(100));
        }

        let result = match self
            .query_handler
            .clone()
            .oneshot((query, None))
            .await
            .unwrap()
        {
            Ok((result, _)) => result,
            Err(QueryExecutionError::CertifiedStateUnavailable) => {
                panic!("Certified state unavailable for query call.")
            }
        };
        if let Ok(WasmResult::Reply(result)) = result.clone() {
            info!(
                "Response{}: {}",
                match result.len() {
                    0..=99 => "".to_string(),
                    _ => format!(" (first 100/{} bytes)", result.len()),
                },
                match result.len() {
                    0..=99 => String::from_utf8_lossy(&result),
                    _ => String::from_utf8_lossy(&result[..100]),
                }
            )
        };

        result
    }

    pub fn ingress<M: ToString, P: Into<Vec<u8>>>(
        &self,
        canister_id: CanisterId,
        method_name: M,
        payload: P,
    ) -> Result<WasmResult, UserError> {
        self.ingress_with_nonce(canister_id, method_name, payload, self.get_nonce())
    }

    pub fn ingress_with_sender<M: ToString, P: Into<Vec<u8>>>(
        &self,
        canister_id: CanisterId,
        method_name: M,
        payload: P,
        sender: &Sender,
    ) -> Result<WasmResult, UserError> {
        process_ingress(
            &self.ingress_sender,
            self.ingress_history_reader.as_ref(),
            SignedIngressBuilder::new()
                .expiry_time(expiry_time_from_now())
                .canister_id(canister_id)
                .method_name(method_name.to_string())
                .method_payload(payload.into())
                .nonce(self.get_nonce())
                .sign_for_sender(sender)
                .build(),
            self.ingress_time_limit,
        )
    }

    pub fn ingress_with_expiry_and_nonce<M: ToString, P: Into<Vec<u8>>>(
        &self,
        canister_id: CanisterId,
        method_name: M,
        payload: P,
        expiry_time: Time,
        nonce: u64,
    ) -> Result<WasmResult, UserError> {
        process_ingress(
            &self.ingress_sender,
            self.ingress_history_reader.as_ref(),
            SignedIngressBuilder::new()
                .expiry_time(expiry_time)
                .canister_id(canister_id)
                .method_name(method_name.to_string())
                .method_payload(payload.into())
                .nonce(nonce)
                .build(),
            self.ingress_time_limit,
        )
    }

    pub fn ingress_with_nonce<M: ToString, P: Into<Vec<u8>>>(
        &self,
        canister_id: CanisterId,
        method_name: M,
        payload: P,
        nonce: u64,
    ) -> Result<WasmResult, UserError> {
        process_ingress(
            &self.ingress_sender,
            self.ingress_history_reader.as_ref(),
            SignedIngressBuilder::new()
                .expiry_time(expiry_time_from_now())
                .canister_id(canister_id)
                .method_name(method_name.to_string())
                .method_payload(payload.into())
                .nonce(nonce)
                .build(),
            self.ingress_time_limit,
        )
    }
}

/// A simple wrapper for bundling the universal canister and the test runtime.
pub struct UniversalCanister {
    pub runtime: LocalTestRuntime,
    pub canister_id: CanisterId,
}

impl UniversalCanister {
    pub fn canister_id(&self) -> CanisterId {
        self.canister_id
    }
    pub fn node_id(&self) -> NodeId {
        self.runtime.node_id
    }

    pub async fn query<P: Into<Vec<u8>>>(&self, payload: P) -> Result<WasmResult, UserError> {
        self.runtime
            .query(self.canister_id(), "query", payload.into())
            .await
    }

    pub fn update<P: Into<Vec<u8>>>(&self, payload: P) -> Result<WasmResult, UserError> {
        self.runtime
            .ingress(self.canister_id(), "update", payload.into())
    }
}

pub struct UniversalCanisterWithStateMachine<'a> {
    env: &'a StateMachine,
    canister_id: CanisterId,
}

impl<'a> UniversalCanisterWithStateMachine<'a> {
    pub fn canister_id(&self) -> CanisterId {
        self.canister_id
    }

    pub fn query<P: Into<Vec<u8>>>(&self, payload: P) -> Result<WasmResult, UserError> {
        self.env.query(self.canister_id(), "query", payload.into())
    }

    pub fn update<P: Into<Vec<u8>>>(&self, payload: P) -> Result<WasmResult, UserError> {
        self.env
            .execute_ingress(self.canister_id(), "update", payload.into())
    }
}

pub fn install_universal_canister<P: Into<Vec<u8>>>(
    env: &StateMachine,
    args: P,
) -> UniversalCanisterWithStateMachine<'_> {
    let canister_id = env
        .install_canister(UNIVERSAL_CANISTER_WASM.to_vec(), args.into(), None)
        .expect("failed to install universal canister");
    UniversalCanisterWithStateMachine { env, canister_id }
}

pub fn assert_reject(res: Result<WasmResult, UserError>, reject_code: RejectCode) {
    match res {
        Ok(WasmResult::Reject(rej)) => assert_eq!(rej.as_bytes()[0], reject_code as u8),
        _ => unreachable!("Assert reject failed."),
    }
}

pub fn assert_reply(res: Result<WasmResult, UserError>, bytes: &[u8]) {
    match res {
        Ok(WasmResult::Reply(res)) => assert_eq!(res.as_slice(), bytes),
        other_response => unreachable!(
            "Assert reply failed. Response received: {:?}",
            other_response
        ),
    }
}
