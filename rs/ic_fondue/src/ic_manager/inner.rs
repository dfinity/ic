use ic_config::{artifact_pool::ArtifactPoolTomlConfig, http_handler};
use ic_config::{
    crypto::CryptoConfig,
    logger::{Config as LoggerConfig, LogTarget},
    metrics::Config as MetricsConfig,
    registry_client::{Config as RegistryClientConfig, DataProviderConfig},
    state_manager::Config as StateManagerConfig,
    ConfigOptional as ReplicaConfig,
};
use ic_prep_lib::initialized_subnet::InitializedSubnet;
use ic_prep_lib::internet_computer::{IcConfig, InitializedIc, TopologyConfig};
use ic_prep_lib::node::{InitializedNode, NodeConfiguration, NodeIndex};
use ic_prep_lib::prep_state_directory::IcPrepStateDir;
use ic_prep_lib::subnet_configuration::SubnetConfig;
use ic_types::ReplicaVersion;
use ic_types::{
    malicious_behaviour::MaliciousBehaviour,
    transport::{TransportConfig, TransportFlowConfig},
    SubnetId,
};
use ic_utils::command::find_file_on_path;
use std::io::Write;
use std::process::Command;
use std::{
    process,
    sync::{Arc, RwLock},
};

use crate::internet_computer::InternetComputer;
use crate::node_software_version::NodeSoftwareVersion;
use crate::port_allocator::{AddrType, EphemeralPortAllocator, TcpAddrAllocator, VmAddrAllocator};
use fondue::log::{debug, info, warn, Logger};
use fondue::manager::process_pool::{self, ManagedProcessCfg};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use nix::unistd::Pid;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

use super::{IcEndpoint, RuntimeDescriptor};
use crossbeam_channel::Receiver;
use ic_config::metrics::Exporter;
use ic_registry_subnet_type::SubnetType;
use process_pool::Signal;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct IcManager {
    pub(crate) inner: Arc<RwLock<IcManagerInner>>,
    /// The working dir used by ic-prep. This dir is deleted as soon as
    /// `IcManager` goes out of scope.
    pub prep_working_dir: Arc<TempDir>,
    /// Tracks the PIDs of the nodes that were configured with malicious
    /// behavior. Currently, this is initialized in `start()` and does *not*
    /// change during the test.
    pub malicious_pids: BTreeSet<Pid>,
    pub(crate) logger: slog::Logger,
    pub(crate) signal_receiver: Arc<RwLock<Receiver<Option<i32>>>>,
}

///The manager consists in a wrapping of process_pool::ProcessPool.
pub struct IcManagerInner {
    pub(crate) procman: process_pool::ProcessPool<NodeCommand>,

    /// Keeps our mio::Registry around
    pub(crate) registry: mio::Registry,
}

impl IcManagerInner {
    pub fn new(pool: process_pool::ProcessPool<NodeCommand>, r: mio::Registry) -> Self {
        IcManagerInner {
            procman: pool,
            registry: r,
        }
    }
}

/// Represents the command that starts an individual node.
#[derive(Clone, Debug)]
pub struct NodeCommand {
    pub cup_dir: PathBuf,
    pub replica_bin_dir: PathBuf,
    pub config_path: PathBuf,
    pub config: ReplicaConfig,
    pub p2p_port: u16,
    pub metrics_port: u16,
    pub http_addr: std::net::SocketAddr,
    pub is_root_subnet: bool,
    // indicates whether this node was configured to exert malicious behavior.
    pub is_malicious: bool,
    // The listening address on which the nodemanager should export its metrics.
    pub nodemanager_metrics_listen_addr: SocketAddr,

    pub initial_subnet_type: SubnetType,

    pub subnet_id: SubnetId,
}

type MaliciousNodes = BTreeMap<NodeIndex, MaliciousBehaviour>;

impl IcManager {
    pub fn restart_node(&mut self, ep: &mut IcEndpoint) {
        if let RuntimeDescriptor::Process(pid) = &mut ep.runtime_descriptor {
            debug!(self.logger, "Attempting to restart process {}", pid);

            let mut inner = self.inner.write().unwrap();
            let mut reg = inner.registry.try_clone().unwrap();
            info!(
                self.logger,
                "Attempting to SIGTERM process and wait (this might orphan the process!)."
            );
            let wait_before_restart = Duration::from_secs(10);
            if let Some(new_pid) =
                inner
                    .procman
                    .restart_process(pid, &mut reg, Signal::SIGTERM, wait_before_restart)
            {
                debug!(self.logger, "Successful restart. New pid is {}", new_pid);
                ep.started_at = Instant::now();
                *pid = new_pid;
            } else {
                warn!(
                    self.logger,
                    "Could not restart process, unexisting pid {}", pid
                );
            }
        } else {
            panic!("Cannot call restart_node on an external endpoint: {:?}", ep);
        }
    }

    /// Initialize an Internet Computer: Bootstrap the Internet Computer
    /// described by `ic` using `prep_dir` as the working_dir (containing crypto
    /// state of the nodes and the initial registry).
    ///
    /// Returns a vector of NodeCommands that can be run by the
    pub(crate) fn synthesize_ic_commands<P: AsRef<Path>>(
        logger: &Logger,
        ic: &InternetComputer,
        prep_dir: P,
    ) -> Vec<NodeCommand> {
        let initialize_ic = |addr_allocator: &mut dyn TcpAddrAllocator| {
            Self::initialize_ic(logger, ic, prep_dir, addr_allocator)
        };
        if ic.experimental_vm_test {
            // XXX: This will be replaced with actual addresses
            let num_addrs = ic.subnets.iter().map(|s| s.nodes.len()).sum();
            let addrs: Vec<IpAddr> = (0..num_addrs)
                .map(|i| IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, i as u16)))
                .collect();
            let mut addr_allocator = VmAddrAllocator::new(addrs);
            let (initialized_ic, malicious_nodes) = initialize_ic(&mut addr_allocator);

            // assemble target path
            let cfg_img_dir = tempfile::tempdir().expect("Could not create temporary directory");
            // for each node, run create-config-image.
            for (subnet_idx, subnet) in initialized_ic.initialized_topology {
                for (node_idx, node) in subnet.initialized_nodes {
                    let ip_addr = addr_allocator
                        .get_addr(subnet_idx as usize, node_idx as usize, AddrType::P2P)
                        .ip();

                    let mut cmd = Command::new("build-bootstrap-config-image.sh");
                    let target_file = PathBuf::from(cfg_img_dir.path())
                        .join(format!("node_{}_{}", subnet_idx, node_idx,));

                    cmd.arg(target_file.clone())
                        .arg("--ipv6_address")
                        .arg(ip_addr.to_string()) //
                        .arg("--ipv6_gateway")
                        .arg(ip_addr.to_string()) // XXX: need to change this to the correct setting
                        .arg("--ic_registry_local_store")
                        .arg(initialized_ic.target_dir.join("ic_registry_local_store"))
                        .arg("--ic_crypto")
                        .arg(node.crypto_path());

                    let output = cmd
                        .output()
                        .expect("could not spawn image creation process");

                    println!("status: {}", output.status);
                    std::io::stdout().write_all(&output.stdout).unwrap();
                    std::io::stderr().write_all(&output.stderr).unwrap();

                    let mut cmd = Command::new("sha256sum");
                    cmd.arg(target_file);

                    let output = cmd
                        .output()
                        .expect("could not spawn image creation process");

                    println!("status: {}", output.status);
                    std::io::stdout().write_all(&output.stdout).unwrap();
                    std::io::stderr().write_all(&output.stderr).unwrap();
                }
            }
            let mut cmd = Command::new("ls");
            cmd.arg("-lah").arg(cfg_img_dir.path());
            let output = cmd
                .output()
                .expect("could not spawn image creation process");

            println!("status: {}", output.status);
            std::io::stdout().write_all(&output.stdout).unwrap();
            std::io::stderr().write_all(&output.stderr).unwrap();
            vec![]
        } else {
            // System Tests
            let mut addr_allocator = EphemeralPortAllocator::new();
            let (initialized_ic, malicious_nodes) = initialize_ic(&mut addr_allocator);

            // All replicas read the registry content from the local store that is on disk.
            let data_provider_config = DataProviderConfig::LocalStore(
                initialized_ic.target_dir.join("ic_registry_local_store"),
            );

            initialized_ic
                .initialized_topology
                .iter()
                .flat_map(|(idx, init_subnet)| {
                    let is_root_subnet = *idx == 0;

                    debug!(
                        logger,
                        "Synthesizing commands for subnet {}", init_subnet.subnet_id
                    );
                    Self::synthesize_subnet_commands(
                        logger,
                        init_subnet,
                        data_provider_config.clone(),
                        &malicious_nodes,
                        is_root_subnet,
                        init_subnet.subnet_config.subnet_type,
                        ic.subnets[(*idx as usize)].node_config.clone(),
                        &mut addr_allocator,
                    )
                })
                .collect()
        }
    }

    /// Initializes an `InternetComputer` using `ic-prep` using `prep_dir` as
    /// the working dir. Returns the initialized IC alongside a map that maps
    /// node indices to the corresponding expected malicious behavior.
    pub(crate) fn initialize_ic<P: AsRef<Path>>(
        logger: &Logger,
        ic: &InternetComputer,
        prep_dir: P,
        addr_allocator: &mut dyn TcpAddrAllocator,
    ) -> (InitializedIc, MaliciousNodes) {
        let mut next_node_index = 0u64;
        let mut port_by_node_index: BTreeMap<NodeIndex, u16> = Default::default();
        let working_dir = PathBuf::from(prep_dir.as_ref());
        let mut malicious_nodes: MaliciousNodes = Default::default();

        // TopologyConfig is a structure provided by ic-prep. We translate from the
        // builder (InternetComputer) to TopologyConfig. While doing so, we allocate tcp
        // ports for the http handler, p2p and xnet. The corresponding sockets are
        // closed when the port-allocator is dropped—which happens before we start the
        // nodes.
        let mut ic_topology = TopologyConfig::default();
        for (subnet_idx, subnet) in ic.subnets.iter().enumerate() {
            let subnet_index = subnet_idx as u64;
            let mut nodes: BTreeMap<NodeIndex, NodeConfiguration> = BTreeMap::new();

            for node in subnet.nodes.iter() {
                let node_index = next_node_index;
                next_node_index += 1;
                let public_api =
                    addr_allocator.get_addr(subnet_idx, node_index as usize, AddrType::PublicApi);
                port_by_node_index.insert(node_index, public_api.port());
                nodes.insert(
                    node_index,
                    NodeConfiguration {
                        xnet_api: vec![addr_allocator
                            .get_addr(subnet_idx, node_index as usize, AddrType::Xnet)
                            .into()],
                        public_api: vec![public_api.into()],
                        private_api: vec![],
                        p2p_addr: format!(
                            "org.internetcomputer.p2p1://{}",
                            addr_allocator.get_addr(subnet_idx, node_index as usize, AddrType::P2P)
                        )
                        .parse()
                        .expect("can't fail"),
                        p2p_num_flows: 1,
                        p2p_start_flow_tag: 1234,
                        prometheus_metrics: vec![addr_allocator
                            .get_addr(subnet_idx, node_index as usize, AddrType::Prometheus)
                            .into()],
                        // this value will be overridden by IcConfig::with_node_operator()
                        node_operator_principal_id: None,
                    },
                );
                if let Some(malicious_behaviour) = &node.malicious_behaviour {
                    malicious_nodes.insert(node_index, malicious_behaviour.clone());
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
                    subnet.subnet_type,
                    subnet.max_instructions_per_message,
                    subnet.max_instructions_per_round,
                    subnet.max_instructions_per_install_code,
                    subnet.features.clone(),
                    subnet.max_number_of_canisters,
                    subnet.ssh_readonly_access.clone(),
                    subnet.ssh_backup_access.clone(),
                ),
            );
        }

        let initial_replica = ic
            .initial_version
            .clone()
            .unwrap_or_else(|| NodeSoftwareVersion::system_test_current(Default::default()));
        debug!(logger, "Using initial replica: {:?}", initial_replica);

        // ic-prep allows a declaring any of the subnets to be the NNS subnet. In our
        // case, however, it's always the first subnet.
        let nns_subnet_idx = Some(0);

        let whitelist = ProvisionalWhitelist::All;
        let ic_config = IcConfig::new(
            working_dir.as_path(),
            ic_topology,
            Some(initial_replica.replica_version),
            // To maintain backwards compatibility, pass true here.
            // False is used only when nodes need to be deployed without
            // them joining any subnet initially

            /* generate_subnet_records= */
            true,
            // We assume by default that the subnet with index 0 is the NNS subnet.
            /* nns_subnet_index= */
            nns_subnet_idx,
            None, // release_package_url
            None, // release_package_sha256_hex
            Some(whitelist),
            ic.node_operator,
            ic.node_provider,
            ic.ssh_readonly_access_to_unassigned_nodes.clone(),
        );

        debug!(logger, "ic_config.initialize");
        let init_ic = ic_config.initialize().expect("can't fail");

        IcPrepStateDir::new(init_ic.target_dir.as_path());
        (init_ic, malicious_nodes)
    }

    /// Generates configuration and synthesizes node commands for a given
    /// subnet.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn synthesize_subnet_commands(
        logger: &Logger,
        init_subnet: &InitializedSubnet,
        registry_data_provider_config: DataProviderConfig,
        malicious_behaviours: &BTreeMap<NodeIndex, MaliciousBehaviour>,
        is_root_subnet: bool,
        initial_subnet_type: SubnetType,
        replica_config: ReplicaConfig,
        port_allocator: &mut dyn TcpAddrAllocator,
    ) -> Vec<NodeCommand> {
        let local_store_path =
            if let DataProviderConfig::LocalStore(p) = registry_data_provider_config {
                p
            } else {
                panic!("Need to configure local store path.");
            };
        init_subnet
            .initialized_nodes
            .iter()
            .map(|(node_index, init_node)| {
                let malicious_behaviour = malicious_behaviours.get(node_index);

                assert!(local_store_path.is_dir());
                let mut options = fs_extra::dir::CopyOptions::new();
                options.copy_inside = true;
                fs_extra::dir::copy(
                    local_store_path.as_path(),
                    init_node.node_path.as_path(),
                    &options,
                )
                .expect("Could not copy local store");
                let mut node_local_store_path = init_node.node_path.clone();
                node_local_store_path.push("ic_registry_local_store");
                let registry_data_provider_config =
                    DataProviderConfig::LocalStore(node_local_store_path);

                let config = Self::create_node_config(
                    registry_data_provider_config,
                    init_node,
                    malicious_behaviour.cloned(),
                    replica_config.clone(),
                );

                Self::synthesize_node_command(
                    logger,
                    config,
                    init_node,
                    is_root_subnet,
                    initial_subnet_type,
                    init_subnet.subnet_id,
                    malicious_behaviour.cloned(),
                    port_allocator.get_addr(
                        init_subnet.subnet_index as usize,
                        *node_index as usize,
                        AddrType::NodemanagerPrometheus,
                    ),
                )
            })
            .collect()
    }

    /// Given an init_node, creates a NodeCommand. Assumes that the node's
    /// config is located under `<init_node.node_path>/ic.json5`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn synthesize_node_command(
        logger: &Logger,
        config: ReplicaConfig,
        init_node: &InitializedNode,
        is_root_subnet: bool,
        initial_subnet_type: SubnetType,
        subnet_id: SubnetId,
        malicious_behaviour: Option<MaliciousBehaviour>,
        metrics_socket_addr: SocketAddr,
    ) -> NodeCommand {
        let cup_dir = tempfile::tempdir().expect("Could not create temp cup dir for node");
        let bin_dir = tempfile::tempdir().expect("Could not create temp binary dir for node");
        let config_path = init_node.node_path.join("ic.json5");

        NodeCommand {
            cup_dir: PathBuf::from(cup_dir.as_ref()),
            replica_bin_dir: PathBuf::from(bin_dir.as_ref()),
            config_path,
            config,
            p2p_port: SocketAddr::from(&init_node.node_config.p2p_addr).port(),
            metrics_port: SocketAddr::from(&init_node.node_config.prometheus_metrics[0]).port(),
            http_addr: SocketAddr::from(&init_node.node_config.public_api[0]),
            is_root_subnet,
            is_malicious: matches!(malicious_behaviour, Some(m) if m.allow_malicious_behaviour),
            nodemanager_metrics_listen_addr: metrics_socket_addr,
            initial_subnet_type,
            subnet_id,
        }
    }

    /// Generates a ic.json5 in the directory `init_node.node_path` using the
    /// provided configurations.
    fn create_node_config(
        registry_data_provider_config: DataProviderConfig,
        init_node: &InitializedNode,
        malicious_behaviour: Option<MaliciousBehaviour>,
        mut replica_config: ReplicaConfig,
    ) -> ReplicaConfig {
        let node_path = init_node.node_path.clone();
        let config_path = node_path.join("ic.json5");
        let state_manager_root = node_path.join("state_manager");
        let artifact_pool_root = node_path.join("artifact_pool");
        let crypto_root = init_node.crypto_path();
        let p2p_port = SocketAddr::from(&init_node.node_config.p2p_addr).port();
        let metrics_addr = SocketAddr::from(&init_node.node_config.prometheus_metrics[0]);
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

        // Here we use a placeholder for the log file for the replica and the
        // nodemanager.  As these files need to be recreated every time the
        // process starts, the corresponding paths will be set in situ with temp
        // files when spawning the command.
        let place_holder_path = PathBuf::from("/placeholder");
        let logger_config = Some(LoggerConfig {
            level: slog::Level::Info,
            format: ic_config::logger::LogFormat::Json,
            target: ic_config::logger::LogTarget::File(place_holder_path.clone()),
            debug_overrides: vec![
                "ic_consensus::consensus::batch_delivery".to_string(),
                "ic_consensus::consensus::catchup_package_maker".to_string(),
            ],
            // Ensure that all messages are logged, even when the internal async log channel
            // overflows.
            block_on_overflow: true,
            ..LoggerConfig::default()
        });

        let nodemanager_logger_config = logger_config.clone().map(|c| LoggerConfig {
            target: ic_config::logger::LogTarget::File(place_holder_path),
            ..c
        });

        replica_config.logger = logger_config;
        replica_config.nodemanager_logger = nodemanager_logger_config;
        replica_config.malicious_behaviour = malicious_behaviour;
        replica_config
    }
}

/// The Config object should be enough to craft a process::Command, which
/// will spawn the replica.
impl ManagedProcessCfg for NodeCommand {
    fn command(&mut self) -> process::Command {
        fn path_to_str<P: AsRef<Path>>(p: P) -> String {
            p.as_ref()
                .to_str()
                .expect("Could not convert path to String")
                .to_string()
        }

        let cup_dir = path_to_str(&self.cup_dir);
        let replica_bin_dir = path_to_str(&self.replica_bin_dir);
        let config_path = path_to_str(&self.config_path);
        let version_file_path = self
            .config_path
            .parent()
            .expect("Could not deduce parent of config_path.")
            .join("version.txt");
        // The version that we use here must match the version that the subnet
        // this node belongs to is bootstrapped with (i.e. the version that is
        // contained in the initial registry version). As system tests do not
        // support scenarios (anymore) during which the node software is
        // upgraded, we assume the version to always be the default version.
        let default_version = ReplicaVersion::default();
        std::fs::write(&version_file_path, default_version.to_string().as_bytes())
            .expect("Could not write version.txt");
        // Search for the directory containing the replica binary and pass it to
        // the nodemanager explicitly.
        let ic_binary_dir = find_file_on_path("replica").expect("Could not find replica on path.");
        let ic_binary_dir = ic_binary_dir.parent().expect("Could not deduce parent.");

        set_log_path(self.config.logger.as_mut());
        set_log_path(self.config.nodemanager_logger.as_mut());
        let config_json = serde_json::to_string(&self.config).unwrap();
        std::fs::write(&self.config_path, config_json.into_bytes()).unwrap();

        let mut cmd = process::Command::new("nodemanager");

        // Currently, the framework has no support for reading metrics from either the
        // nodemanager or the replica and thus let the nodemanager assign a
        // OS-chosen port.

        cmd.arg("--metrics-listen-addr")
            .arg(self.nodemanager_metrics_listen_addr.to_string())
            .arg("--cup-dir")
            .arg(cup_dir)
            .arg("--replica-binary-dir")
            .arg(replica_bin_dir)
            .arg("--replica-config-file")
            .arg(config_path)
            .arg("--ic-binary-directory")
            .arg(ic_binary_dir);

        // Specifying version-file will prevent the system-tests to work on MacOS.
        let os = std::env::consts::OS;
        if !"macos".to_string().eq(os) {
            cmd.arg("--version-file").arg(version_file_path);
        }
        cmd
    }

    fn auxiliary_info_source(&self) -> Vec<PathBuf> {
        vec![
            logger_config_to_file(self.config.logger.as_ref()),
            logger_config_to_file(self.config.nodemanager_logger.as_ref()),
        ]
        .into_iter()
        .flatten()
        .collect()
    }
}

fn logger_config_to_file(opt_log_cfg: Option<&LoggerConfig>) -> Option<PathBuf> {
    opt_log_cfg.and_then(|l| {
        if let LogTarget::File(p) = &l.target {
            Some(p.clone())
        } else {
            None
        }
    })
}

fn set_log_path(opt_log_cfg: Option<&mut LoggerConfig>) {
    if let Some(cfg) = opt_log_cfg {
        let is_file = matches!(&cfg.target, LogTarget::File(p));

        if is_file {
            cfg.target = LogTarget::File(get_temp_file_path());
        }
    }
}

fn get_temp_file_path() -> PathBuf {
    let fifo_tmp_file =
        tempfile::NamedTempFile::new().expect("Could not create temp fifo file for node");
    let fifo_tmp_file = fifo_tmp_file.into_temp_path();
    let fifo_path = fifo_tmp_file.to_path_buf();
    fifo_tmp_file
        .close()
        .expect("Could not close temp fifo file in order to make temp fifo fifo");
    nix::unistd::mkfifo(&fifo_path, nix::sys::stat::Mode::S_IRWXU).expect("Couldn't create fifo");
    fifo_path
}
