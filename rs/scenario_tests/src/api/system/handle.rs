use crate::api::handle::{Ic, Node, Subnet};
use crate::port_allocator::TcpPortAllocator;
use crate::system_test::InternetComputer;
use canister_test::*;
use dfn_candid::candid;
use futures::stream::StreamExt;
use futures::{future, stream};
use ic_base_types::PrincipalId;
use ic_canister_client::{Agent, HttpClient, Sender};
use ic_config::{artifact_pool::ArtifactPoolTomlConfig, http_handler};
use ic_config::{
    crypto::CryptoConfig,
    logger::Config as LoggerConfig,
    metrics::{Config as MetricsConfig, Exporter},
    registry_client::{Config as RegistryClientConfig, DataProviderConfig},
    state_manager::Config as StateManagerConfig,
    ConfigOptional as ReplicaConfig,
};
use ic_crypto_sha::Sha256;
use ic_interfaces::registry::{RegistryDataProvider, ZERO_REGISTRY_VERSION};
use ic_logger::{info, warn, LoggerImpl, ReplicaLogger};
use ic_nns_common::types::{NeuronId, ProposalId};
use ic_nns_constants::{
    ids::TEST_NEURON_1_OWNER_KEYPAIR, GOVERNANCE_CANISTER_ID, REGISTRY_CANISTER_ID,
};
use ic_nns_governance::pb::v1::{NnsFunction, Vote};
use ic_nns_test_utils::{
    governance::{execute_eligible_proposals, submit_external_update_proposal},
    ids::TEST_NEURON_1_ID,
    itest_helpers::{NnsCanisters, NnsInitPayloadsBuilder},
};
use ic_prep_lib::initialized_subnet::InitializedSubnet;
use ic_prep_lib::internet_computer::{IcConfig, InitializedIc, TopologyConfig};
use ic_prep_lib::node::{InitializedNode, NodeConfiguration, NodeIndex};
use ic_prep_lib::subnet_configuration::SubnetConfig;
use ic_registry_common::proto_registry_data_provider::ProtoRegistryDataProvider;
use ic_registry_common::registry::RegistryCanister;
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_type::SubnetType;
use ic_registry_transport::pb::v1::{RegistryAtomicMutateRequest, RegistryMutation};
use ic_release::release::{ReleaseContent, NODEMANAGER_KEY, REPLICA_KEY};
use ic_test_utilities::types::ids::node_id_to_u64;
use ic_types::{
    malicious_behaviour::MaliciousBehaviour,
    transport::{TransportConfig, TransportFlowConfig},
    CanisterId, NodeId, ReplicaVersion, SubnetId,
};
use ic_utils::command::find_file_on_path;
use process_manager::process_manager::{
    ManagedCommand, ProcessEvent, ProcessManager, ProcessManagerEvent, ProcessManagerResult, Source,
};
use registry_canister::mutations::{
    do_bless_replica_version::BlessReplicaVersionPayload,
    do_update_subnet_replica::UpdateSubnetReplicaVersionPayload,
};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::{future::Future, net::SocketAddr};
use tempfile::TempDir;
use tokio::{task::JoinHandle, time::sleep};
use url::Url;

pub type SystemTestResult<T> = Result<T, SystemTestError>;

#[derive(Debug)]
pub enum SystemTestError {
    UnknownError,
    InvalidState,
    /// Returned when calling a function that requires an NNS and no NNS is
    /// present in the current configuration.
    NnsNotPresent,
    InitializationError(String),
    InternalError(String),
}

pub enum NodeState {
    /// The node is registered with the IC.
    Registered,
    /// The node is assigned to a subnetwork.
    Assigned,
    /// The node is about to be removed from a subnetwork.
    ToBeRemoved,
}

pub struct NodeHandle {
    id: NodeId,
    ic_instance: Arc<IcHandle>,
}

async fn send_post_request(
    http_client: &reqwest::Client,
    url: &str,
    timeout: Duration,
) -> Result<(Vec<u8>, reqwest::StatusCode), String> {
    let resp = http_client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/cbor")
        .timeout(timeout)
        .send()
        .await
        .map_err(|err| format!("sending post request failed with {}: ", err))?;
    let resp_status = resp.status();
    let resp_body = resp
        .bytes()
        .await
        .map_err(|err| format!("receive post response failed with {}: ", err))?
        .to_vec();
    Ok((resp_body, resp_status))
}

impl NodeHandle {
    pub(crate) fn new(id: NodeId, ic_instance: Arc<IcHandle>) -> Self {
        Self { id, ic_instance }
    }

    pub fn id(&self) -> NodeId {
        self.id
    }

    /// Sends a post to the node's `api/v2/status` and awaits for a reply.
    /// In case we see a request error, it can be that the node is still not
    /// listening, so we wait some seconds and try again, until we waited for
    /// timeout_s seconds. Returns `false` when we waited timeout_s without an
    /// answer.
    pub async fn ready_timeout(&self, timeout_s: std::time::Duration) -> bool {
        let my_url = self.api_url().join("api/v2/status").unwrap();

        println!("Request status for {};", my_url);

        let http_client = reqwest::Client::new();

        // We'lll send requests until the client is responsive or
        // timeout_s time has passed. Because Duration::is_zero is still
        // only in nightly, we the condition on the while loop is about the
        // time left being greather than zero.
        //
        // Finally, each time we get a OS error, we wait for timeout_s/8 time
        // before trying again.
        let mut timeout_left = timeout_s;
        let timeout_slice = timeout_s / 8;
        loop {
            let res = send_post_request(&http_client, my_url.as_str(), timeout_left).await;

            match res {
                Ok((_, _)) => {
                    return true;
                }
                Err(e) => {
                    info!(
                        self.ic_instance.log,
                        "{} not ready retrying in {:?} ({:?}), err = {}",
                        my_url,
                        timeout_slice,
                        timeout_left.as_millis(),
                        e,
                    );
                    if timeout_left.ge(&timeout_slice) {
                        sleep(timeout_slice).await;
                        timeout_left -= timeout_slice;
                    } else {
                        return false;
                    }
                }
            }
        }
    }

    /// An agent that targets this node.
    pub fn api(&self) -> Runtime {
        Runtime::Remote(RemoteTestRuntime {
            agent: Agent::new_with_client(
                self.ic_instance.agent_client.clone(),
                self.api_url(),
                Sender::from_keypair(&ic_test_identity::TEST_IDENTITY_KEYPAIR),
            ),
        })
    }

    pub fn api_url(&self) -> Url {
        self.ic_instance.node_api_url(self.id)
    }

    pub fn start(&self) -> SystemTestResult<()> {
        self.ic_instance
            .initialized_ic
            .initialized_topology
            .iter()
            .flat_map(|(_subnet_id, init_subnet)| init_subnet.initialized_nodes.values())
            .find_map(|init_node| {
                if init_node.node_id == self.id {
                    Some((init_node.node_id, init_node))
                } else {
                    None
                }
            })
            .map(|(node_id, init_node)| {
                start_process_for_init_node(&self.ic_instance.process_manager, &node_id, init_node)
                    .map_err(|e| SystemTestError::InternalError(format!("{:?}", e)))
            })
            .expect("Could not find node path.")
    }

    pub fn kill(&self) -> SystemTestResult<()> {
        self.ic_instance
            .process_manager
            .terminate_process(&self.id.to_string())
            .map_err(|e| SystemTestError::InternalError(e.to_string()))?;
        Ok(())
    }

    pub async fn assign_to_subnet(_subnet: SubnetId) -> SystemTestResult<()> {
        unimplemented!()
    }
}

pub struct SubnetHandle {
    id: SubnetId,
    nodes: Vec<NodeId>,
    ic_instance: Arc<IcHandle>,
}

impl SubnetHandle {
    pub(crate) fn new(id: SubnetId, nodes: Vec<NodeId>, ic_instance: Arc<IcHandle>) -> Self {
        Self {
            id,
            nodes,
            ic_instance,
        }
    }

    pub fn id(&self) -> SubnetId {
        self.id
    }

    /// Waits until said this subnet has at least quorum_f(self.nodes.len())
    /// nodes ready. Most of the time, quorum_f will be (|tot| tot), but in case
    /// the user wants to setup malicious nodes, they might need to /not/ wait
    /// for nodes that refuse to answer.
    pub async fn ready_timeout(
        &self,
        timeout_s: std::time::Duration,
        quorum_f: fn(usize) -> usize,
    ) -> bool {
        let nodes: Vec<_> = self
            .node_ids()
            .into_iter()
            .map(|nid| self.node(nid))
            .collect();

        //Since f is not a parameter anywhere, we compute the largest f
        //for this subnet.
        let tot = nodes.len();

        //We now poll all nodes in the subnet for their status
        //by creating a buffer_unordered then calling next f+1 times.
        let mut is = stream::iter(nodes.into_iter())
            .map(|nhd| async move { nhd.ready_timeout(timeout_s).await })
            .buffer_unordered(tot);

        for _k in 0..quorum_f(tot) {
            match is.next().await {
                Some(true) => continue,
                _ => return false,
            }
        }

        info!(
            self.ic_instance.log,
            "Subnet {} ready;",
            self.id().to_string()
        );

        true
    }

    pub fn node_by_idx(&self, idx: usize) -> NodeHandle {
        NodeHandle::new(self.nodes[idx], self.ic_instance.clone())
    }

    pub fn node(&self, id: NodeId) -> NodeHandle {
        assert!(self.nodes.contains(&id));
        NodeHandle::new(id, self.ic_instance.clone())
    }

    pub fn node_ids(&self) -> Vec<NodeId> {
        self.nodes.clone()
    }

    /// Get the public API of a random node on this subnet.
    pub fn api(&self) -> Runtime {
        self.random_node().api()
    }

    pub fn random_node(&self) -> NodeHandle {
        let idx = rand::random::<usize>() % self.nodes.len();
        self.node_by_idx(idx)
    }

    /// Sets the version_id for this subnetwork and returns the new registry
    /// version.
    pub async fn set_replica_version(&self, version_id: String) -> SystemTestResult<()> {
        let log = self.ic_instance.log.clone();
        let nns_api = self.ic_instance.nns_api()?;
        let max_duration = Duration::from_secs(30);
        retry_for_duration(log, max_duration, || {
            update_subnet_replica_version(&nns_api, self.id, version_id.clone())
        })
        .await
    }
}

/// Helper struct that awaits the given future on drop.
struct JoinOnDrop<T> {
    future: Option<JoinHandle<T>>,
}

impl<T> Drop for JoinOnDrop<T> {
    fn drop(&mut self) {
        if let Some(f) = self.future.take() {
            futures::executor::block_on(f).unwrap();
        }
    }
}

/// In a test, `IcHandle` represents an instance of the Internet Computer under
/// test. It provides an API to access and manipulate the state of the IC, its
/// topology and nodes.
pub struct IcHandle {
    /// We need to retain the LoggerImpl as it contains a guard that, when
    /// dropped, destroys the async log drain. As we want to keep IcHandle
    /// cloneable, we store the LoggerImpl in an Arc.
    _logger_impl: LoggerImpl,

    #[allow(dead_code)]
    log: ReplicaLogger,

    /// An object representation a fixed initialized configuration of the
    /// InternetComputer.
    pub(crate) initialized_ic: InitializedIc,

    // We want to retain the same agent client for all http connections.
    #[allow(dead_code)]
    agent_client: HttpClient,

    // mock out some api calls for demo purposes
    cheat: bool,

    // maps a node id to a corresponding port
    node_ports: BTreeMap<NodeId, u16>,

    process_manager: ProcessManager,

    /// Indicates whether there is a NNS subnet present in the current topology.
    nns_subnet_present: bool,

    /// The working directory where all of the state is stored. On drop of
    /// `_working_dir`, the corresponding directory will be cleaned up.
    _working_dir: TempDir,

    /// Future to join when dropping this. `process_manager` must have been
    /// dropped before or this will deadlock.
    _process_event_dispatcher: JoinOnDrop<()>,
}

impl IcHandle {
    pub async fn from_internet_computer(
        ic: InternetComputer,
        log: ReplicaLogger,
        logger_impl: LoggerImpl,
        actix_flag: bool,
    ) -> SystemTestResult<Arc<Self>> {
        let initial_replica = InitialReplica::default();
        info!(log, "Using initial replica: {:?}", initial_replica);

        let mut next_node_index = 1u64;
        let mut port_by_node_index: BTreeMap<NodeIndex, u16> = Default::default();
        let working_dir = tempfile::tempdir().expect("Could not create temporary directory");
        let mut malicious_behaviours: BTreeMap<NodeIndex, MaliciousBehaviour> = BTreeMap::new();
        let mut port_allocators: BTreeMap<u64, TcpPortAllocator> = Default::default();

        let mut process_manager = ProcessManager::new();
        let stream = process_manager
            .take_stream()
            .expect("Could not get event stream.");

        let fut = tokio::task::spawn(dispatch_process_events(
            stream,
            log.clone(),
            // Arc::new(RwLock::new(analyzer)),
        ));

        let initialized_ic = {
            // we close the sockets of the port allocator at the end of this scope.
            let mut ic_topology = TopologyConfig::default();
            for (subnet_idx, subnet) in ic.subnets.iter().enumerate() {
                let subnet_index = subnet_idx as u64;
                let mut port_allocator = TcpPortAllocator::new();
                let mut nodes: BTreeMap<NodeIndex, NodeConfiguration> = BTreeMap::new();

                for node in subnet.nodes.iter() {
                    let node_index = next_node_index;
                    next_node_index += 1;
                    let http_addr = port_allocator.next().unwrap();
                    port_by_node_index.insert(node_index, http_addr.port());
                    nodes.insert(
                        node_index,
                        NodeConfiguration {
                            xnet_api: vec![port_allocator.next().unwrap().into()],
                            public_api: vec![http_addr.into()],
                            private_api: vec![],
                            p2p_addr: format!(
                                "org.internetcomputer.p2p1://{}",
                                port_allocator.next().unwrap()
                            )
                            .parse()
                            .expect("can't fail"),
                            p2p_num_flows: 1,
                            p2p_start_flow_tag: 1234,
                            prometheus_metrics: vec![port_allocator.next().unwrap().into()],
                            node_operator_principal_id: None,
                        },
                    );
                    if let Some(malicious_behaviour) = &node.malicious_behaviour {
                        malicious_behaviours.insert(node_index, malicious_behaviour.clone());
                    }
                }

                ic_topology.insert_subnet(
                    subnet_index,
                    SubnetConfig::new(
                        subnet_index,
                        nodes,
                        None,
                        subnet.ingress_bytes_per_block_soft_cap,
                        subnet.max_ingress_bytes_per_message,
                        subnet.max_ingress_messages_per_block,
                        subnet.max_block_payload_size,
                        subnet.unit_delay,
                        subnet.initial_notary_delay,
                        subnet.dkg_interval_length,
                        subnet.dkg_dealings_per_block,
                        SubnetType::System,
                        subnet.max_instructions_per_message,
                        subnet.max_instructions_per_round,
                        subnet.max_instructions_per_install_code,
                        None,
                        subnet.max_number_of_canisters,
                        vec![],
                        vec![],
                    ),
                );

                port_allocators.insert(subnet_index, port_allocator);
            }

            let (replica_url, replica_sha256_hex) = get_replica_url_and_hash();

            let whitelist = ProvisionalWhitelist::All;
            let mut ic_config = IcConfig::new(
                working_dir.path(),
                ic_topology,
                Some(initial_replica.version_id.clone()),
                Some(replica_url),
                Some(replica_sha256_hex),
                // To maintain backwards compatibility, pass true here.
                // False is used only when nodes need to be deployed without
                // them joining any subnet initially
                /* generate_subnet_records= */
                true,
                /* nns_subnet_index= */ port_allocators.iter().next().map(|a| *a.0),
                None,
                None,
                None,
                None,
                Some(whitelist),
                None,
                None,
                vec![],
            );

            ic_config
                .initial_mutations
                .append(&mut ic.initial_mutations.clone());

            ic_config
                .initialize()
                .map_err(|e| SystemTestError::InitializationError(e.to_string()))
        }?;

        let nns_subnet_index = if ic.nns_subnet_present {
            port_allocators.iter().next().map(|a| *a.0)
        } else {
            None
        };

        let data_provider_config = DataProviderConfig::LocalStore(
            initialized_ic.target_dir.join("ic_registry_local_store"),
        );

        // if there is an NNS subnetwork, start the nns subnetwork and return the
        // registry data provider to be used by the remaining network.
        if let Some(nns_subnet_index) = nns_subnet_index {
            let init_nns_subnet = initialized_ic.initialized_topology.iter().next().unwrap().1;
            let registry_canister_url: Url = init_nns_subnet
                .initialized_nodes
                .iter()
                .next()
                .unwrap()
                .1
                .node_config
                .public_api[0]
                .clone()
                .into();

            info!(log, "Starting NNS");
            Self::start_subnet(
                init_nns_subnet,
                data_provider_config.clone(),
                port_allocators
                    .remove(&nns_subnet_index)
                    .expect("No port allocator for nns subnet."),
                &process_manager,
                &malicious_behaviours,
            )
            .await;

            info!(log, "Initializing NNS subnet.");
            let api = Runtime::Remote(RemoteTestRuntime {
                agent: Agent::new(registry_canister_url.clone(), Sender::Anonymous),
            });

            info!(log, "Building and installing nns canisters.");
            let init_payloads = NnsInitPayloadsBuilder::new()
                .with_initial_mutations(vec![RegistryAtomicMutateRequest {
                    mutations: read_initial_registry_mutations(initialized_ic.registry_path()),
                    ..Default::default()
                }])
                .build();
            NnsCanisters::set_up(&api, init_payloads).await;
        }

        // if we have an nns subnet, it is the first in the iteration and we skip it.
        for (_, init_subnet) in initialized_ic
            .initialized_topology
            .iter()
            .skip(ic.nns_subnet_present as usize)
        {
            info!(log, "Starting remaining subnet {}", init_subnet.subnet_id);
            Self::start_subnet(
                init_subnet,
                data_provider_config.clone(),
                port_allocators
                    .remove(&init_subnet.subnet_index)
                    .expect("No port allocator found for subnet."),
                &process_manager,
                &malicious_behaviours,
            )
            .await;
        }

        // Translate port_by_node_index to node_ports.
        let mut index_to_id: BTreeMap<NodeIndex, NodeId> = BTreeMap::new();
        for init_subnet in initialized_ic.initialized_topology.values() {
            for (node_index, init_node) in init_subnet.initialized_nodes.iter() {
                index_to_id.insert(*node_index, init_node.node_id);
            }
        }
        let mut node_ports: BTreeMap<NodeId, u16> = Default::default();
        port_by_node_index.iter().for_each(|(node_index, port)| {
            node_ports.insert(*index_to_id.get(node_index).unwrap(), *port);
        });

        Ok(Arc::new(Self {
            _logger_impl: logger_impl,
            log,
            nns_subnet_present: ic.nns_subnet_present,
            initialized_ic,
            agent_client: HttpClient::new(),
            cheat: false,
            node_ports,
            process_manager,
            _working_dir: working_dir,
            _process_event_dispatcher: JoinOnDrop {
                future: if actix_flag { None } else { Some(fut) },
            },
        }))
    }

    /// Wait for the IC to be ready for at most timeout_s seconds;
    /// We define the IC being ready when all of its subnets have
    /// a quorum of nodes that are responsive.
    pub async fn ready_timeout(
        self: Arc<Self>,
        timeout_s: std::time::Duration,
        quorum_f: fn(usize) -> usize,
    ) -> Option<Arc<Self>> {
        let snets = self.subnet_ids().into_iter().map(|sid| self.subnet(sid));

        let vec_rdy = future::join_all(
            snets.map(|s| async move { s.ready_timeout(timeout_s, quorum_f).await }),
        )
        .await;

        for rdy in vec_rdy.into_iter() {
            if !rdy {
                return None;
            }
        }

        Some(self)
    }

    /// Waits for the IC to be ready for at most 90 seconds.
    /// check ready_timeout_quorum.
    pub async fn ready(self: Arc<Self>) -> Option<Arc<Self>> {
        self.ready_timeout(Duration::from_secs(90), |tot| tot).await
    }

    /// Iterator over subnet ids.
    pub fn subnet_ids(&self) -> Vec<SubnetId> {
        self.topology()
            .values()
            .cloned()
            .map(|v| v.subnet_id)
            .collect()
    }

    pub fn subnet(self: &Arc<Self>, id: SubnetId) -> SubnetHandle {
        let nodes = self
            .topology()
            .values()
            .find(|v| v.subnet_id == id)
            .unwrap();
        SubnetHandle::new(
            id,
            nodes
                .initialized_nodes
                .values()
                .map(|init_node| init_node.node_id)
                .collect(),
            self.clone(),
        )
    }

    /// register a new node with the internet computer.
    pub fn register_node(&self) -> SystemTestResult<NodeHandle> {
        unimplemented!()
    }

    /// If an NNS subnet is configured, adds a new entry for a registry version.
    pub async fn add_replica_version(
        self: &Arc<Self>,
        version_id: String,
        binary_url: String,
        sha256_hex: String,
        release_package_url: String,
        release_package_sha256_hex: String,
    ) -> SystemTestResult<()> {
        let nns_api = self.nns_api()?;
        add_replica_version(
            &nns_api,
            version_id,
            binary_url,
            sha256_hex,
            release_package_url,
            release_package_sha256_hex,
        )
        .await
    }

    fn topology(&self) -> &BTreeMap<u64, InitializedSubnet> {
        &self.initialized_ic.initialized_topology
    }

    pub fn agent_client(&self) -> &HttpClient {
        &self.agent_client
    }

    /// Url for the Public Api of node `node_id`. Internally, `IcInstance` will
    /// manage a mapping of node-id to URL. Note: Whenever a node is
    /// (re)started, potentially, a new port is assigned.
    pub fn node_api_url(&self, node_id: NodeId) -> Url {
        if self.cheat {
            Url::parse("http://localhost:8080/").unwrap()
        } else {
            let port = self
                .node_ports
                .get(&node_id)
                .expect("could not find node in node port map");
            Url::parse(&format!("http://localhost:{}/", port)).unwrap()
        }
    }

    /// If an NNS is initialized, will return a `RegistryCanister` abstracting
    /// the registry canister installed on the NNS.
    #[allow(dead_code)]
    pub fn registry_canister(self: &Arc<Self>) -> SystemTestResult<RegistryCanister> {
        let nns_subnet = self.nns_subnet()?;
        let api_url = nns_subnet.node_by_idx(0).api_url();
        Ok(RegistryCanister::new(vec![api_url]))
    }

    /// If an NNS is initialized, will return a `Runtime` abstracting the public
    /// API of the first node on the NNS subnet.
    pub fn nns_api(self: &Arc<Self>) -> SystemTestResult<Runtime> {
        let nns_subnet = self.nns_subnet()?;
        Ok(nns_subnet.node_by_idx(0).api())
    }

    /// If an NNS is initialized, will return a handle for the NNS subnet.
    pub fn nns_subnet(self: &Arc<Self>) -> SystemTestResult<SubnetHandle> {
        if !self.nns_subnet_present {
            return Err(SystemTestError::NnsNotPresent);
        }
        // XXX: Here we rely on the NNS subnet being the first in the order of subnet by
        // ids. This might change in the future.
        Ok(self.subnet_by_idx(0))
    }

    /// Retrieve a subnet by index. The order of subnets is arbitrary.
    pub fn subnet_by_idx(self: &Arc<Self>, idx: u64) -> SubnetHandle {
        let init_subnet = &self.initialized_ic.initialized_topology[&idx];
        SubnetHandle::new(
            init_subnet.subnet_id,
            init_subnet
                .initialized_nodes
                .values()
                .map(|init_node| init_node.node_id)
                .collect(),
            self.clone(),
        )
    }

    /// Generates a ic.json5 in the directory `init_node.node_path`.
    #[allow(clippy::too_many_arguments)]
    pub fn generate_replica_config(
        registry_data_provider_config: DataProviderConfig,
        node_id: NodeId,
        init_node: &InitializedNode,
        malicious_behaviour: Option<MaliciousBehaviour>,
        metrics_addr: SocketAddr,
    ) {
        let mut replica_config = ReplicaConfig::default();

        let node_path = init_node.node_path.clone();
        let config_path = node_path.join("ic.json5");
        let state_manager_root = node_path.join("state_manager");
        let artifact_pool_root = node_path.join("artifact_pool");
        let crypto_root = init_node.crypto_path();
        let p2p_port = SocketAddr::from(&init_node.node_config.p2p_addr).port();
        let http_addr = SocketAddr::from(&init_node.node_config.public_api[0]);

        replica_config.transport = Some(TransportConfig {
            node_ip: SocketAddr::from(&init_node.node_config.p2p_addr)
                .ip()
                .to_string(),
            p2p_flows: vec![TransportFlowConfig {
                flow_tag: 1234,
                server_port: p2p_port,
                queue_size: 256,
            }],
        });
        replica_config.state_manager = Some(StateManagerConfig::new(state_manager_root));
        replica_config.http_handler = Some(http_handler::ExternalConfig {
            listen_addr: Some(http_addr),
            ..Default::default()
        });
        replica_config.metrics = Some(MetricsConfig {
            exporter: Exporter::Http(metrics_addr),
        });
        replica_config.artifact_pool = Some(ArtifactPoolTomlConfig::new(artifact_pool_root, None));
        replica_config.crypto = Some(CryptoConfig::new(crypto_root));
        replica_config.registry_client = Some(RegistryClientConfig {
            data_provider: Some(registry_data_provider_config),
        });

        let logger_config = LoggerConfig {
            node_id: node_id_to_u64(node_id),
            level: slog::Level::Info,
            format: ic_config::logger::LogFormat::Json,
            target: ic_config::logger::LogTarget::Stderr,
            ..LoggerConfig::default()
        };
        replica_config.logger = Some(logger_config);
        replica_config.malicious_behaviour = malicious_behaviour;

        let config_json = serde_json::to_string(&replica_config).unwrap();
        std::fs::write(config_path, config_json.into_bytes()).unwrap();
    }

    /// Prepares all replicas processes for a subnet.
    pub async fn start_subnet(
        init_subnet: &InitializedSubnet,
        registry_data_provider_config: DataProviderConfig,
        mut port_allocator: TcpPortAllocator,
        process_manager: &ProcessManager,
        malicious_behaviours: &BTreeMap<NodeIndex, MaliciousBehaviour>,
    ) {
        for (node_index, init_node) in init_subnet.initialized_nodes.iter() {
            let metrics_addr = port_allocator.next().expect("Could not allocate address");
            let malicious_behaviour = malicious_behaviours.get(node_index);
            let node_id = init_node.node_id;
            Self::generate_replica_config(
                registry_data_provider_config.clone(),
                node_id,
                init_node,
                malicious_behaviour.cloned(),
                metrics_addr,
            );
            start_process_for_init_node(process_manager, &node_id, init_node)
                .expect("Could not start node process.");
        }

        // frees all ports that were allocated for this subnet
        std::mem::drop(port_allocator);
    }
}

#[derive(Debug, Clone)]
pub struct InitialReplica {
    url: Url,
    version_id: ReplicaVersion,
    hash: Option<String>,
}

impl InitialReplica {
    pub fn new_from_url(url: Url) -> Self {
        Self {
            url,
            version_id: ReplicaVersion::default(),
            hash: None,
        }
    }
}

impl Default for InitialReplica {
    fn default() -> Self {
        Self {
            url: get_replica_url().expect("Could not get replica URL."),
            version_id: ReplicaVersion::default(),
            hash: None,
        }
    }
}

fn read_initial_registry_mutations<P: AsRef<Path>>(path: P) -> Vec<RegistryMutation> {
    let initial_registry = ProtoRegistryDataProvider::load_from_file(path.as_ref());
    // Because we use the ProtoRegistryDataProvider, we are guaranteed to get
    // the entire registry in one chunk when calling `get_updates_since()`.
    let records = initial_registry
        .get_updates_since(ZERO_REGISTRY_VERSION)
        .expect("Could not load records from initial registry.");

    records
        .into_iter()
        .filter(|r| r.value.is_some())
        .map(|r| RegistryMutation {
            mutation_type: 0,
            key: r.key.as_bytes().to_vec(),
            value: r.value.unwrap(),
        })
        .collect()
}

/// Adds the given `ReplicaVersionRecord` to the registry and returns the
/// registry version after the update.
async fn add_replica_version(
    nns_api: &'_ Runtime,
    replica_version_id: String,
    binary_url: String,
    sha256_hex: String,
    release_package_url: String,
    release_package_sha256_hex: String,
) -> SystemTestResult<()> {
    let governance_canister = get_canister(nns_api, GOVERNANCE_CANISTER_ID);
    let proposal_payload = BlessReplicaVersionPayload {
        replica_version_id,
        binary_url,
        sha256_hex,
        node_manager_binary_url: "".into(),
        node_manager_sha256_hex: "".into(),
        release_package_url,
        release_package_sha256_hex,
    };

    let proposal_id: ProposalId = submit_external_update_proposal(
        &governance_canister,
        Sender::from_keypair(&TEST_NEURON_1_OWNER_KEYPAIR),
        NeuronId(TEST_NEURON_1_ID),
        NnsFunction::BlessReplicaVersion,
        proposal_payload,
        "<proposal created by add_replica_version>".to_string(),
        "".to_string(),
    )
    .await;

    vote_and_execute_proposal(&governance_canister, proposal_id).await;

    Ok(())
}

/// Send an update-call to the upgrade-canister on the NNS asking for Subnet
/// `subnet_id` to be updated to replica with version id `replica_version_id`.
async fn update_subnet_replica_version(
    nns_api: &'_ Runtime,
    subnet_id: SubnetId,
    replica_version_id: String,
) -> SystemTestResult<()> {
    let upgrades_canister = get_canister(nns_api, REGISTRY_CANISTER_ID);
    let set_to_blessed_ = UpdateSubnetReplicaVersionPayload {
        subnet_id: subnet_id.get(),
        replica_version_id,
    };
    let response_set_to_blessed: Result<(), String> = upgrades_canister
        .update_("update_subnet_replica_version", candid, (set_to_blessed_,))
        .await;
    response_set_to_blessed.map_err(SystemTestError::InternalError)?;
    Ok(())
}

/// Votes for and executes the proposal identified by `proposal_id`.
async fn vote_and_execute_proposal(governance_canister: &Canister<'_>, proposal_id: ProposalId) {
    // Cast votes.
    let input = (TEST_NEURON_1_ID, proposal_id, Vote::Yes);
    let _result: Result<(), String> = governance_canister
        .update_("forward_vote", candid, input)
        .await
        .expect("Vote failed");

    execute_eligible_proposals(governance_canister).await;
}

pub fn get_canister(nns_api: &'_ Runtime, canister_id: CanisterId) -> Canister<'_> {
    Canister::new(nns_api, canister_id)
}

async fn retry_for_duration<T, F, Fut>(
    log: ReplicaLogger,
    max_duration: Duration,
    mut f: F,
) -> SystemTestResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = SystemTestResult<T>>,
{
    let start = std::time::Instant::now();
    let delay = Duration::from_millis(250);
    let mut time_left = max_duration;
    while time_left > Duration::from_secs(0) {
        match tokio::time::timeout(time_left, f()).await {
            Ok(Ok(v)) => return Ok(v),
            Ok(Err(e)) => warn!(log, "Attempt failed: {:?}. Retry in 250 ms.", e),
            Err(_) => break,
        }
        sleep(delay).await;
        // timeout may not become negative
        time_left = max_duration - start.elapsed().max(max_duration);
    }
    Err(SystemTestError::InternalError(
        "Operation timed out.".to_string(),
    ))
}

/// Dispatches process events from the process manager:
/// * prints stdout/err lines from the process
/// * Logs errors and state changes from the process
pub async fn dispatch_process_events(
    event_stream: impl futures::stream::Stream<Item = ProcessManagerEvent>,
    log: ReplicaLogger,
    // analyzer: Arc<RwLock<Analyzer<'static, LogEntryFrom>>>,
) {
    event_stream
        .for_each(|event| async {
            use ProcessEvent::*;
            let ProcessManagerEvent { handle, event } = event;

            match event {
                OutputLine(Source::Stdout, line) => {
                    println!("{}: {}", handle, line);
                }
                OutputLine(Source::Stderr, line) => {
                    eprintln!("{}: {}", handle, line);

                    //Now we shall feed the lines into the analyzer if they are
                    // valid log entries.
                    // let handleline = format!("{}: {}", handle, line);
                    // let log_entry_res = FromStr::from_str(&handleline);
                    // match &log_entry_res {
                    //     Ok(log_entry) => {
                    //         if let Err(err) =
                    // analyzer.write().unwrap().observe_event(log_entry) {
                    //             pm.signal_all_processes_and_clear(
                    //                 nix::sys::signal::Signal::SIGTERM,
                    //             )
                    //             .unwrap_or(());
                    //             println!("LOG_ANALYZER FAILURES: {:?}", err);
                    //             std::process::exit(1);
                    //         }
                    //     }
                    //     Err(e) => {
                    //         eprintln!("CANT PARSE: {:?}", e);
                    //     }
                    // }
                }
                Exited(error) => {
                    info!(log, "{} exited with exit status: {:?}", handle, error);
                }
                StateChange(process_state) => info!(log, "{:?}", process_state),
                IoError(error) => {
                    warn!(log, "{} err: {:?}", handle, error);
                }
            }
        })
        .await;
}

/// Finds the replica on the path and returns a `file:///`-URL pointing to the found replica.
pub fn get_replica_url() -> Option<Url> {
    find_file_on_path("replica").map(|path| {
        Url::parse(&format!(
            "file://{}",
            path.as_path()
                .as_os_str()
                .to_str()
                .expect("Failed to obtain path string from PathBuf")
        ))
        .expect("Failed to parse URL")
    })
}

/// Returns a URL to the replica on path, and the hash of this replica binary
pub fn get_replica_url_and_hash() -> (Url, String) {
    let replica = find_file_on_path("replica").expect("Could not find replica on $PATH");

    let mut replica_file =
        std::fs::File::open(&replica).unwrap_or_else(|_| panic!("Failed to open {:?}", &replica));

    let mut hasher = Sha256::new();
    std::io::copy(&mut replica_file, &mut hasher)
        .unwrap_or_else(|_| panic!("Failed to compute hash of {:?}", &replica_file));

    let hash = hex::encode(hasher.finish());

    let url = Url::parse(&format!(
        "file://{}",
        replica
            .as_path()
            .as_os_str()
            .to_str()
            .expect("Failed to obtain path string from PathBuf")
    ))
    .expect("Failed to construct URL from a file");

    (url, hash)
}

/// Return the file URL to a release package tarball and the hash of this
/// tarball
pub fn get_release_package(dir: &Path) -> (Url, String) {
    let replica = find_file_on_path("replica").expect("Could not find replica on $PATH");

    let node_manager =
        find_file_on_path("nodemanager").expect("Could not find nodemanager on $PATH");

    let mut release_content = ReleaseContent::default();
    release_content.add_entry(REPLICA_KEY, replica);
    release_content.add_entry(NODEMANAGER_KEY, node_manager);

    let tar_path = dir.join("release_package.tar.gz");
    release_content
        .pack(&tar_path)
        .expect("Failed to pack release package");

    let mut tar_file =
        std::fs::File::open(&tar_path).unwrap_or_else(|_| panic!("Failed to open {:?}", &tar_path));

    let mut hasher = Sha256::new();
    std::io::copy(&mut tar_file, &mut hasher)
        .unwrap_or_else(|_| panic!("Failed to compute hash of {:?}", &tar_path));

    let hash = hex::encode(hasher.finish());

    let url = Url::parse(&format!(
        "file://{}",
        tar_path
            .as_path()
            .as_os_str()
            .to_str()
            .expect("Failed to obtain path string from PathBuf")
    ))
    .expect("Failed to construct URL from a file");

    (url, hash)
}

struct TempNodeDirectories {
    pub cup_dir: TempDir,
    pub replica_bin_dir: TempDir,
}

impl Default for TempNodeDirectories {
    fn default() -> Self {
        Self {
            cup_dir: tempfile::tempdir().expect("Could not create temp_dir for node."),
            replica_bin_dir: tempfile::tempdir().expect("Could not create temp_dir for node."),
        }
    }
}

fn start_process_for_init_node(
    process_manager: &ProcessManager,
    node_id: &NodeId,
    init_node: &InitializedNode,
) -> ProcessManagerResult<()> {
    let temp_node_dirs = TempNodeDirectories::default();
    let cup_dir = temp_node_dirs
        .cup_dir
        .path()
        .to_str()
        .expect("Failed to transform cup path into string.")
        .to_string();
    let replica_bin_dir = temp_node_dirs
        .replica_bin_dir
        .path()
        .to_str()
        .expect("Failed to transform replica bin path into string")
        .to_string();

    let args = vec![
        // in legacy mode, we need to make sure the nodemanager
        // runs in test mode to not use a fixed port for metrics.
        "--metrics-listen-addr".to_string(),
        "0.0.0.0:0".to_string(),
        "--cup-dir".to_string(),
        cup_dir,
        "--replica-binary-dir".to_string(),
        replica_bin_dir,
        "--replica-config-file".to_string(),
        init_node
            .node_path
            .join("ic.json5")
            .as_path()
            .to_str()
            .unwrap()
            .to_string(),
    ];

    process_manager.start_process_with_drop_handler(
        &node_id.to_string(),
        ManagedCommand::new("nodemanager".to_string(), args).terminate_on_drop(),
        Box::new(temp_node_dirs),
    )
}

impl Ic for Arc<IcHandle> {
    fn subnet_ids(&self) -> Vec<SubnetId> {
        IcHandle::subnet_ids(self)
    }

    fn subnet(&self, id: SubnetId) -> Box<dyn Subnet> {
        Box::new(IcHandle::subnet(self, id))
    }

    fn route(&self, _: PrincipalId) -> Option<SubnetId> {
        None
    }

    fn get_principal(&self) -> Option<PrincipalId> {
        None
    }
}

impl Subnet for SubnetHandle {
    fn node_by_idx(&self, idx: usize) -> Box<dyn Node> {
        Box::new(self.node_by_idx(idx))
    }

    fn node(&self, id: NodeId) -> Box<dyn Node> {
        Box::new(self.node(id))
    }
}

impl Node for NodeHandle {
    /// An agent that targets this node.
    fn api(&self) -> Runtime {
        self.api()
    }
}
