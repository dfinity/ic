use ic_config::subnet_config::SubnetConfig;
use ic_config::subnet_config::SubnetConfigs;
use ic_cycles_account_manager::CyclesAccountManager;
use ic_execution_environment::setup_execution;
use ic_interfaces::registry::RegistryClient;
use ic_interfaces::{
    execution_environment::{IngressHistoryReader, QueryHandler},
    messaging::MessageRouting,
    state_manager::{CertificationScope, StateHashError, StateManager, StateReader},
};
use ic_logger::ReplicaLogger;
use ic_messaging::MessageRoutingImpl;
use ic_metrics::MetricsRegistry;
use ic_protobuf::registry::{
    provisional_whitelist::v1::ProvisionalWhitelist as PbProvisionalWhitelist,
    routing_table::v1::RoutingTable as PbRoutingTable,
};
use ic_protobuf::types::v1::PrincipalId as PrincipalIdIdProto;
use ic_protobuf::types::v1::SubnetId as SubnetIdProto;
use ic_registry_client_fake::FakeRegistryClient;
use ic_registry_keys::{
    make_provisional_whitelist_record_key, make_routing_table_record_key, ROOT_SUBNET_ID_KEY,
};
use ic_registry_proto_data_provider::ProtoRegistryDataProvider;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_routing_table::{routing_table_insert_subnet, CanisterIdRange, RoutingTable};
use ic_registry_subnet_type::SubnetType;
use ic_replicated_state::ReplicatedState;
use ic_state_manager::StateManagerImpl;
use ic_test_utilities::{
    consensus::fake::FakeVerifier,
    mock_time,
    registry::{add_subnet_record, insert_initial_dkg_transcript, SubnetRecordBuilder},
    types::messages::SignedIngressBuilder,
};
use ic_types::batch::SelfValidatingPayload;
use ic_types::{
    batch::{Batch, BatchPayload, IngressPayload, XNetPayload},
    ic00,
    ic00::{CanisterIdRecord, CanisterSettingsArgs, InstallCodeArgs, Method, Payload},
    ingress::{IngressStatus, WasmResult},
    messages::{CanisterInstallMode, MessageId, SignedIngress, UserQuery},
    time::Time,
    user_error::UserError,
    CanisterId, CryptoHashOfState, NodeId, PrincipalId, Randomness, RegistryVersion, SubnetId,
    UserId,
};
use std::fmt;
use std::path::Path;
use std::string::ToString;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// Constructs the initial version of the registry containing a subnet with the
/// specified SUBNET_ID, with the node with the specified NODE_ID assigned to
/// it.
fn make_single_node_registry(
    subnet_id: SubnetId,
    subnet_type: SubnetType,
    node_id: NodeId,
) -> (Arc<ProtoRegistryDataProvider>, Arc<FakeRegistryClient>) {
    let registry_version = RegistryVersion::from(1);
    let data_provider = Arc::new(ProtoRegistryDataProvider::new());

    let root_subnet_id_proto = SubnetIdProto {
        principal_id: Some(PrincipalIdIdProto {
            raw: subnet_id.get_ref().to_vec(),
        }),
    };
    data_provider
        .add(
            ROOT_SUBNET_ID_KEY,
            registry_version,
            Some(root_subnet_id_proto),
        )
        .unwrap();

    let mut routing_table = RoutingTable::new();
    routing_table_insert_subnet(&mut routing_table, subnet_id).unwrap();
    let pb_routing_table = PbRoutingTable::from(routing_table);
    data_provider
        .add(
            &make_routing_table_record_key(),
            registry_version,
            Some(pb_routing_table),
        )
        .unwrap();
    let pb_whitelist = PbProvisionalWhitelist::from(ProvisionalWhitelist::All);
    data_provider
        .add(
            &make_provisional_whitelist_record_key(),
            registry_version,
            Some(pb_whitelist),
        )
        .unwrap();

    // Set subnetwork list(needed for filling network_topology.nns_subnet_id)
    let mut record = SubnetRecordBuilder::from(&[node_id]).build();
    record.subnet_type = i32::from(subnet_type);

    insert_initial_dkg_transcript(registry_version.get(), subnet_id, &record, &data_provider);
    add_subnet_record(&data_provider, registry_version.get(), subnet_id, record);

    let registry_client = Arc::new(FakeRegistryClient::new(Arc::clone(&data_provider) as _));
    registry_client.update_to_latest_version();
    (data_provider, registry_client)
}

/// Represents a replicated state machine detached from the network layer that
/// can be used to test this part of the stack in isolation.
pub struct StateMachine {
    registry_data_provider: Arc<ProtoRegistryDataProvider>,
    registry_client: Arc<FakeRegistryClient>,
    state_manager: Arc<StateManagerImpl>,
    message_routing: MessageRoutingImpl,
    ingress_history_reader: Box<dyn IngressHistoryReader>,
    query_handler: Arc<dyn QueryHandler<State = ReplicatedState>>,
    state_dir: TempDir,
    nonce: std::cell::Cell<u64>,
    time: std::cell::Cell<Time>,
}

impl Default for StateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for StateMachine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StateMachine")
            .field("state_dir", &self.state_dir.path().display())
            .field("nonce", &self.nonce.get())
            .finish()
    }
}

impl StateMachine {
    /// Constructs a new environment that uses a temporary directory for storing
    /// states.
    pub fn new() -> Self {
        Self::setup_from_dir(
            TempDir::new().expect("failed to create a temporary directory"),
            0,
            mock_time(),
            None,
        )
    }

    pub fn new_with_config(config: SubnetConfig) -> Self {
        Self::setup_from_dir(
            TempDir::new().expect("failed to create a temporary directory"),
            0,
            mock_time(),
            Some(config),
        )
    }

    /// Constructs and initializes a new state machine that uses the specified
    /// directory for storing states.
    fn setup_from_dir(
        state_dir: TempDir,
        nonce: u64,
        time: Time,
        subnet_config: Option<SubnetConfig>,
    ) -> Self {
        use slog::Drain;

        let decorator = slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let logger = slog::Logger::root(drain, slog::o!());
        let replica_logger: ReplicaLogger = logger.into();

        let subnet_id = SubnetId::from(PrincipalId::new_subnet_test_id(1));
        let node_id = NodeId::from(PrincipalId::new_node_test_id(1));
        let metrics_registry = MetricsRegistry::new();
        let subnet_type = SubnetType::System;
        let subnet_config = match subnet_config {
            Some(subnet_config) => subnet_config,
            None => SubnetConfigs::default().own_subnet_config(subnet_type),
        };

        let (registry_data_provider, registry_client) =
            make_single_node_registry(subnet_id, subnet_type, node_id);

        let sm_config = ic_config::state_manager::Config::new(state_dir.path().to_path_buf());
        let hypervisor_config = ic_config::execution_environment::Config {
            canister_sandboxing_flag: ic_config::flag_status::FlagStatus::Disabled,
            ..Default::default()
        };

        let cycles_account_manager = Arc::new(CyclesAccountManager::new(
            subnet_config.scheduler_config.max_instructions_per_message,
            subnet_type,
            subnet_id,
            subnet_config.cycles_account_manager_config,
        ));
        let state_manager = Arc::new(StateManagerImpl::new(
            Arc::new(FakeVerifier::new()),
            subnet_id,
            subnet_type,
            replica_logger.clone(),
            &metrics_registry,
            &sm_config,
            None,
            ic_types::malicious_flags::MaliciousFlags::default(),
        ));
        let (_, ingress_history_writer, ingress_history_reader, query_handler, _, scheduler) =
            setup_execution(
                replica_logger.clone(),
                &metrics_registry,
                subnet_id,
                subnet_type,
                subnet_config.scheduler_config,
                hypervisor_config.clone(),
                Arc::clone(&cycles_account_manager),
                Arc::clone(&state_manager) as Arc<_>,
            );

        let message_routing = MessageRoutingImpl::new(
            Arc::clone(&state_manager) as _,
            Arc::clone(&state_manager) as _,
            Arc::clone(&ingress_history_writer) as _,
            scheduler,
            hypervisor_config,
            cycles_account_manager,
            subnet_id,
            &metrics_registry,
            replica_logger,
            Arc::clone(&registry_client) as _,
        );

        Self {
            registry_data_provider,
            registry_client,
            state_manager,
            ingress_history_reader,
            message_routing,
            query_handler,
            state_dir,
            nonce: std::cell::Cell::new(nonce),
            time: std::cell::Cell::new(time),
        }
    }

    /// Emulates a node restart, including checkpoint recovery.
    pub fn restart_node(self) -> Self {
        Self::setup_from_dir(self.state_dir, self.nonce.get(), self.time.get(), None)
    }

    pub fn restart_node_with_config(self, config: SubnetConfig) -> Self {
        Self::setup_from_dir(
            self.state_dir,
            self.nonce.get(),
            self.time.get(),
            Some(config),
        )
    }

    /// Creates a new batch containing a single ingress message and sends it for
    /// processing to the replicated state machine.
    fn send_signed_ingress(&self, msg: SignedIngress) {
        // Move the block time forward by 1 second.
        self.time.set(self.time.get() + Duration::from_secs(1));

        let batch = Batch {
            batch_number: self.message_routing.expected_batch_height(),
            requires_full_state_hash: true,
            payload: BatchPayload {
                ingress: IngressPayload::from(vec![msg]),
                xnet: XNetPayload {
                    stream_slices: Default::default(),
                },
                self_validating: SelfValidatingPayload::default(),
            },
            randomness: Randomness::from([0; 32]),
            ecdsa_subnet_public_key: None,
            registry_version: self.registry_client.get_latest_version(),
            time: self.time.get(),
            consensus_responses: vec![],
        };
        self.message_routing
            .deliver_batch(batch)
            .expect("MR queue overflow")
    }

    /// Blocks until the hash of the latest state is computed.
    ///
    /// # Panics
    ///
    /// This function panics if the state hash computation takes more than a few
    /// seconds to complete.
    pub fn await_state_hash(&self) -> CryptoHashOfState {
        let h = self.state_manager.latest_state_height();
        let started_at = Instant::now();
        let mut tries = 0;
        while tries < 100 {
            match self.state_manager.get_state_hash_at(h) {
                Ok(hash) => return hash,
                Err(StateHashError::Transient(_)) => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
                Err(e @ StateHashError::Permanent(_)) => {
                    panic!("Failed to compute state hash: {}", e)
                }
            }
        }
        panic!(
            "State hash computation took too long ({:?})",
            started_at.elapsed()
        )
    }

    /// Blocks until the result of the ingress message with the specified ID is
    /// available.
    ///
    /// # Panics
    ///
    /// This function panics if the result doesn't become available in a
    /// reasonable amount of time (typically, a few seconds).
    pub fn await_ingress(&self, msg_id: MessageId) -> Result<WasmResult, UserError> {
        let mut tries = 0;
        let started_at = Instant::now();
        while tries < 6000 {
            match self.ingress_status(&msg_id) {
                IngressStatus::Completed { result, .. } => return Ok(result),
                IngressStatus::Failed { error, .. } => return Err(error),
                _ => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }
            }
        }
        panic!(
            "did not get answer to ingress {} after {:?}",
            msg_id,
            started_at.elapsed()
        )
    }

    /// Imports a directory containing a canister snapshot into the state machine.
    ///
    /// After you import the canister, you can execute methods on it and upgrade it.
    /// The original directory is not modified.
    ///
    /// The function is currently not used in code, but it is useful for local
    /// testing and debugging. Do not remove it.
    ///
    /// # Panics
    ///
    /// This function panics if loading the canister snapshot fails.
    pub fn import_canister_state<P: AsRef<Path>>(
        &self,
        canister_directory: P,
        canister_id: CanisterId,
    ) {
        let canister_directory = canister_directory.as_ref();
        assert!(
            canister_directory.is_dir(),
            "canister state at {} must be a directory",
            canister_directory.display()
        );

        let tip = self
            .state_manager
            .state_layout()
            .tip(ic_types::Height::new(0))
            .expect("failed to obtain tip");
        let tip_canister_layout = tip
            .canister(&canister_id)
            .expect("failed to obtain writeable canister layout");

        fn copy_as_writeable(src: &Path, dst: &Path) {
            assert!(
                src.is_file(),
                "Canister layout contains only files, but {} is not a file.",
                src.display()
            );
            std::fs::copy(src, dst).expect("failed to copy file");
            let file = std::fs::File::open(dst).expect("failed to open file");
            let mut permissions = file
                .metadata()
                .expect("failed to get file permission")
                .permissions();
            permissions.set_readonly(false);
            file.set_permissions(permissions)
                .expect("failed to set file persmission");
        }

        for entry in std::fs::read_dir(canister_directory).expect("failed to read_dir") {
            let entry = entry.expect("failed to get directory entry");
            copy_as_writeable(
                &entry.path(),
                &tip_canister_layout.raw_path().join(entry.file_name()),
            );
        }

        let canister_state = ic_state_manager::checkpoint::load_canister_state(
            &tip_canister_layout,
            &canister_id,
            ic_types::Height::new(0),
        )
        .unwrap_or_else(|e| {
            panic!(
                "failed to load canister state from {}: {}",
                canister_directory.display(),
                e
            )
        });

        let (h, mut state) = self.state_manager.take_tip();
        state.put_canister_state(canister_state);
        self.state_manager
            .commit_and_certify(state, h.increment(), CertificationScope::Full);
    }

    pub fn install_wasm_in_mode(
        &self,
        canister_id: CanisterId,
        mode: CanisterInstallMode,
        wasm: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<(), UserError> {
        let state = self.state_manager.get_latest_state().take();
        let sender = state
            .canister_state(&canister_id)
            .and_then(|s| s.controllers().iter().next().cloned())
            .unwrap_or_else(PrincipalId::new_anonymous);
        self.execute_ingress_as(
            sender,
            ic00::IC_00,
            Method::InstallCode,
            InstallCodeArgs::new(mode, canister_id, wasm, payload, None, None, None).encode(),
        )
        .map(|_| ())
    }

    /// Compiles specified WAT to Wasm and installs it for the canister using
    /// the specified ID in the provided install mode.
    fn install_wat_in_mode(
        &self,
        canister_id: CanisterId,
        mode: CanisterInstallMode,
        wat: &str,
        payload: Vec<u8>,
    ) {
        self.install_wasm_in_mode(
            canister_id,
            mode,
            wabt::wat2wasm(wat).expect("invalid WAT"),
            payload,
        )
        .expect("failed to install canister");
    }

    /// Creates a new canister and returns the canister principal.
    pub fn create_canister(&self, settings: Option<CanisterSettingsArgs>) -> CanisterId {
        let wasm_result = self
            .execute_ingress(
                ic00::IC_00,
                ic00::Method::ProvisionalCreateCanisterWithCycles,
                ic00::ProvisionalCreateCanisterWithCyclesArgs {
                    amount: Some(candid::Nat::from(0)),
                    settings,
                }
                .encode(),
            )
            .expect("failed to create canister");
        match wasm_result {
            WasmResult::Reply(bytes) => CanisterIdRecord::decode(&bytes[..])
                .expect("failed to decode canister id record")
                .get_canister_id(),
            WasmResult::Reject(reason) => panic!("create_canister call rejected: {}", reason),
        }
    }

    /// Creates a new canister and installs its code.
    /// Returns the ID of the newly created canister.
    ///
    /// This function is synchronous.
    pub fn install_canister(
        &self,
        module: Vec<u8>,
        payload: Vec<u8>,
        settings: Option<CanisterSettingsArgs>,
    ) -> Result<CanisterId, UserError> {
        let canister_id = self.create_canister(settings);
        self.install_wasm_in_mode(canister_id, CanisterInstallMode::Install, module, payload)?;
        Ok(canister_id)
    }

    /// Creates a new canister and installs its code specified by WAT string.
    /// Returns the ID of the newly created canister.
    ///
    /// This function is synchronous.
    ///
    /// # Panics
    ///
    /// Panicks if canister creation or the code install failed.
    pub fn install_canister_wat(
        &self,
        wat: &str,
        payload: Vec<u8>,
        settings: Option<CanisterSettingsArgs>,
    ) -> CanisterId {
        let canister_id = self.create_canister(settings);
        self.install_wat_in_mode(canister_id, CanisterInstallMode::Install, wat, payload);
        canister_id
    }

    /// Erases the previous state and code of the canister with the specified ID
    /// and replaces the code with the compiled form of the provided WAT.
    pub fn reinstall_canister_wat(&self, canister_id: CanisterId, wat: &str, payload: Vec<u8>) {
        self.install_wat_in_mode(canister_id, CanisterInstallMode::Reinstall, wat, payload);
    }

    /// Performs upgrade of the canister with the specified ID to the
    /// code obtained by compiling the provided WAT.
    pub fn upgrade_canister_wat(&self, canister_id: CanisterId, wat: &str, payload: Vec<u8>) {
        self.install_wat_in_mode(canister_id, CanisterInstallMode::Upgrade, wat, payload);
    }

    /// Queries the canister with the specified ID.
    pub fn query(
        &self,
        receiver: CanisterId,
        method: impl ToString,
        method_payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.query_handler.query(
            UserQuery {
                receiver,
                source: UserId::from(PrincipalId::new_anonymous()),
                method_name: method.to_string(),
                method_payload,
                ingress_expiry: 0,
                nonce: None,
            },
            self.state_manager.get_latest_state().take(),
            Vec::new(),
        )
    }

    /// Returns the module hash of the specified canister.
    pub fn module_hash(&self, canister_id: CanisterId) -> Option<[u8; 32]> {
        let state = self.state_manager.get_latest_state().take();
        let canister_state = state.canister_state(&canister_id)?;
        Some(
            canister_state
                .execution_state
                .as_ref()?
                .wasm_binary
                .binary
                .module_hash(),
        )
    }

    /// Executes an ingress message on the canister with the specified ID.
    ///
    /// This function is synchronous, it blocks until the result of the ingress
    /// message is known. The function returns this result.
    ///
    /// # Panics
    ///
    /// This function panics if the status was not ready in a reasonable amount
    /// of time (typically, a few seconds).
    pub fn execute_ingress_as(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
        method: impl ToString,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        let msg_id = self.send_ingress(sender, canister_id, method, payload);
        self.await_ingress(msg_id)
    }

    pub fn execute_ingress(
        &self,
        canister_id: CanisterId,
        method: impl ToString,
        payload: Vec<u8>,
    ) -> Result<WasmResult, UserError> {
        self.execute_ingress_as(PrincipalId::new_anonymous(), canister_id, method, payload)
    }

    /// Sends an ingress message to the canister with the specified ID.
    ///
    /// This function is asynchronous. It returns the ID of the ingress message
    /// that can be awaited later with [await_ingress].
    pub fn send_ingress(
        &self,
        sender: PrincipalId,
        canister_id: CanisterId,
        method: impl ToString,
        payload: Vec<u8>,
    ) -> MessageId {
        self.nonce.set(self.nonce.get() + 1);
        let msg = SignedIngressBuilder::new()
            .sender(UserId::from(sender))
            .canister_id(canister_id)
            .method_name(method.to_string())
            .method_payload(payload)
            .nonce(self.nonce.get())
            .build();
        let msg_id = msg.id();
        self.send_signed_ingress(msg);
        msg_id
    }

    /// Returns the status of the ingress message with the specified ID.
    pub fn ingress_status(&self, msg_id: &MessageId) -> IngressStatus {
        (self.ingress_history_reader.get_latest_status())(msg_id)
    }

    pub fn stop_canister(&self, canister_id: CanisterId) -> Result<WasmResult, UserError> {
        self.execute_ingress(
            CanisterId::ic_00(),
            "stop_canister",
            (CanisterIdRecord::from(canister_id)).encode(),
        )
    }

    /// Updates the routing table so that a range of canisters is assigned to
    /// the specified destination subnet.
    pub fn reroute_canister_range(
        &self,
        canister_range: std::ops::RangeInclusive<CanisterId>,
        destination: SubnetId,
    ) {
        use ic_registry_client_helpers::routing_table::RoutingTableRegistry;

        let last_version = self.registry_client.get_latest_version();
        let next_version = last_version.increment();

        let mut routing_table = self
            .registry_client
            .get_routing_table(last_version)
            .expect("malformed routing table")
            .expect("missing routing table");

        routing_table.assign_range(
            CanisterIdRange {
                start: *canister_range.start(),
                end: *canister_range.end(),
            },
            destination,
        );

        self.registry_data_provider
            .add(
                &make_routing_table_record_key(),
                next_version,
                Some(PbRoutingTable::from(routing_table)),
            )
            .unwrap();
        self.registry_client.update_to_latest_version();

        assert_eq!(next_version, self.registry_client.get_latest_version());
    }
}
