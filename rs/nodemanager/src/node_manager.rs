use crate::args::NodeManagerArgs;
use crate::catch_up_package_provider::CatchUpPackageProvider;
use crate::crypto_helper::setup_crypto;
use crate::firewall::Firewall;
use crate::metrics::NodeManagerMetrics;
use crate::nns_registry_replicator::NnsRegistryReplicator;
use crate::registration::NodeRegistration;
use crate::registry_helper::RegistryHelper;
use crate::release_package::ReleasePackage;
use crate::release_package_provider::ReleasePackageProvider;
use crate::replica_process::ReplicaProcess;
use crate::ssh_access_manager::SshAccessManager;
use crate::utils;
use ic_config::registry_client::DataProviderConfig;
use ic_config::{
    metrics::{Config as MetricsConfig, Exporter},
    Config,
};
use ic_crypto::utils::get_node_keys_or_generate_if_missing;
use ic_crypto::CryptoComponentForNonReplicaProcess;
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces::{crypto::KeyManager, registry::RegistryClient};
use ic_logger::{error, info, new_replica_logger, warn, LoggerImpl, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_metrics_exporter::MetricsRuntimeImpl;
use ic_registry_client::helper::node::NodeRegistry;
use ic_registry_client::helper::subnet::SubnetRegistry;
use ic_registry_common::local_store::{LocalStore, LocalStoreImpl};
use ic_types::{consensus::CatchUpPackage, NodeId, RegistryVersion, ReplicaVersion, SubnetId};
use slog_async::AsyncGuard;
use std::convert::TryFrom;
use std::env;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

pub struct NodeManager {
    pub logger: ReplicaLogger,
    _async_log_guard: AsyncGuard,
    _metrics_runtime: MetricsRuntimeImpl,
    _crypto: Arc<dyn CryptoComponentForNonReplicaProcess + Send + Sync>,
    // for tokio 1.0+ we can use `tokio::task::JoinHandle`
    release_package: Arc<std::sync::atomic::AtomicBool>,
    firewall: Arc<std::sync::atomic::AtomicBool>,
    ssh_access_manager: Arc<std::sync::atomic::AtomicBool>,
    replica_process: Arc<Mutex<ReplicaProcess>>,
}

// Loads the replica version from the file specified as argument on node
// manager's start.
fn load_version_from_file(logger: &ReplicaLogger, path: &Path) -> Result<ReplicaVersion, ()> {
    let contents = std::fs::read_to_string(path).map_err(|err| {
        error!(
            logger,
            "Couldn't open the version file {:?}: {:?}", path, err
        );
    })?;
    ReplicaVersion::try_from(contents.trim()).map_err(|err| {
        error!(
            logger,
            "Couldn't parse the contents of {:?}: {:?}", path, err
        );
    })
}

impl NodeManager {
    /// Start the Node Manager
    ///
    /// This starts 2 tasks for upgrades: one which runs and monitors
    /// a Replica process, and another that constantly monitors for a
    /// new release package that this node should upgrade to and
    /// executes the upgrade to this new release.
    ///
    /// It spawns a third task that monitors the registry for new
    /// data centers. If a new data center is added, node manager will
    /// generate a new firewall configuration allowing access from the
    /// IP range specified in the DC record.
    pub async fn start(args: NodeManagerArgs) -> Result<Self, ()> {
        args.create_dirs();
        let metrics_addr = args.get_metrics_addr();
        let config = args.get_ic_config();
        let (_node_pks, node_id) = get_node_keys_or_generate_if_missing(&config.crypto.crypto_root);

        let (logger, _async_log_guard) = Self::get_logger(&config);
        let slog_logger = logger.inner_logger.root.clone();
        let metrics_registry = MetricsRegistry::global();
        let current_node_manager_hash = utils::get_node_manager_binary_hash()
            .expect("Failed to determine sha256 of node manager binary");

        info!(
            logger,
            "Running node manager ({:?} sha256 hash: {:?}) with upgrade support, config is: {:?}",
            env::current_exe(),
            current_node_manager_hash,
            config
        );

        let registry = Arc::new(RegistryHelper::new_with(
            &metrics_registry,
            &config,
            node_id,
            logger.clone(),
        ));

        let crypto = Arc::new(setup_crypto(
            &config.crypto,
            registry.get_registry_client(),
            logger.clone(),
        ));

        let cup_provider = Arc::new(CatchUpPackageProvider::new(
            Arc::clone(&registry),
            args.cup_dir.clone(),
            crypto.clone(),
            logger.clone(),
        ));

        let replica_version = load_version_from_file(&logger, &args.version_file)?;
        let local_cup = cup_provider.get_local_cup();
        if let Some(cup_with_proto) = local_cup {
            let cup = &cup_with_proto.cup;
            match get_subnet_id(&*registry.registry_client, cup) {
                Ok(subnet_id) => {
                    if !should_node_become_unassigned(
                        &*registry.registry_client,
                        node_id,
                        subnet_id,
                        cup,
                    ) {
                        // unassign node
                    }
                }
                Err(err) => error!(&logger, "Couldn't get the subnet_id: {:?}", err),
            }
        }

        // we only support the local store data provider
        let local_store_path = if let DataProviderConfig::LocalStore(path) = config
            .registry_client
            .data_provider
            .clone()
            .expect("registry data provider is not configured")
        {
            path
        } else {
            panic!("Only LocalStore is supported in the nodemanager.");
        };

        let (metrics, _metrics_runtime) = Self::get_metrics(
            metrics_addr,
            &slog_logger,
            &metrics_registry,
            registry.get_registry_client(),
            crypto.clone(),
        );
        let metrics = Arc::new(metrics);

        let registry_local_store = Arc::new(LocalStoreImpl::new(local_store_path));
        let mut registration = NodeRegistration::new(
            logger.clone(),
            config.clone(),
            Arc::clone(&registry.registry_client),
            Arc::clone(&crypto) as Arc<dyn KeyManager>,
            registry_local_store.clone(),
        );
        // initialize the registry local store. Will not return if the nns is not
        // reachable.
        registration.initialize_local_store().await;

        let nns_registry_replicator = Arc::new(NnsRegistryReplicator::new(
            logger.clone(),
            node_id,
            registry.get_registry_client(),
            registry_local_store as Arc<dyn LocalStore>,
            std::time::Duration::from_millis(config.nns_registry_replicator.poll_delay_duration_ms),
        ));

        if let Err(err) = nns_registry_replicator.fetch_and_start_polling() {
            warn!(logger, "{}", err);
        }

        if args.enable_provisional_registration {
            // will not return until the node is registered
            registration.register_node().await;
        }

        let release_package_provider = Arc::new(ReleasePackageProvider::new(
            Arc::clone(&registry),
            args.replica_binary_dir.clone(),
            args.force_replica_binary.clone(),
            logger.clone(),
        ));

        let slog_logger = logger.inner_logger.root.clone();
        let replica_process = Arc::new(Mutex::new(ReplicaProcess::new(slog_logger.clone())));
        let ic_binary_directory = args
            .ic_binary_directory
            .as_ref()
            .unwrap_or(&PathBuf::from("/tmp"))
            .clone();

        let release_package = ReleasePackage::start(
            Arc::clone(&registry),
            replica_process.clone(),
            release_package_provider,
            cup_provider,
            None, // subnet_id,
            replica_version,
            args.replica_config_file.clone(),
            ic_binary_directory.clone(),
            nns_registry_replicator,
            logger.clone(),
        )
        .await;
        let firewall = Firewall::new(
            Arc::clone(&registry),
            Arc::clone(&metrics),
            config.firewall.clone(),
            logger.clone(),
        )
        .start();
        let ssh_access_manager =
            SshAccessManager::new(Arc::clone(&registry), Arc::clone(&metrics), logger.clone())
                .start();
        Ok(Self {
            logger,
            _async_log_guard,
            _metrics_runtime,
            _crypto: crypto,
            release_package,
            replica_process,
            firewall,
            ssh_access_manager,
        })
    }

    pub fn spawn_wait_and_restart_replica(&self) {
        ReplicaProcess::spawn_wait_and_restart(self.replica_process.clone());
    }

    pub fn stop_replica(&mut self) {
        // Stop checking for new releases.
        self.release_package
            .as_ref()
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.firewall
            .as_ref()
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.ssh_access_manager
            .as_ref()
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let e = self.replica_process.clone().lock().unwrap().stop();
        warn!(self.logger, "unable to stop replica: {:?}", e);
    }

    /// Construct a `ReplicaLogger` and its `AsyncGuard`. If this `AsyncGuard`
    /// is dropped, all asynchronously logged messages will no longer be
    /// output.
    fn get_logger(config: &Config) -> (ReplicaLogger, AsyncGuard) {
        let base_logger = LoggerImpl::new(&config.nodemanager_logger, "nodemanager".into());
        let logger = new_replica_logger(base_logger.root.clone(), &config.logger);

        (logger, base_logger.async_log_guard)
    }

    /// Construct a `NodeManagerMetrics` and its `MetricsRuntimeImpl`. If this
    /// `MetricsRuntimeImpl` is dropped, metrics will no longer be
    /// collected.
    fn get_metrics(
        metrics_addr: SocketAddr,
        logger: &slog::Logger,
        metrics_registry: &MetricsRegistry,
        registry_client: Arc<dyn RegistryClient>,
        crypto: Arc<dyn TlsHandshake + Send + Sync>,
    ) -> (NodeManagerMetrics, MetricsRuntimeImpl) {
        let metrics_config = MetricsConfig {
            exporter: Exporter::Http(metrics_addr),
        };

        let metrics_runtime = MetricsRuntimeImpl::new(
            tokio::runtime::Handle::current(),
            metrics_config,
            metrics_registry.clone(),
            registry_client,
            crypto,
            logger,
        );

        let metrics = NodeManagerMetrics::new(metrics_registry);

        (metrics, metrics_runtime)
    }
}

// Returns the subnet id for the given CUP.
fn get_subnet_id(registry: &dyn RegistryClient, cup: &CatchUpPackage) -> Result<SubnetId, String> {
    let dkg_summary = &cup
        .content
        .block
        .get_value()
        .payload
        .as_ref()
        .as_summary()
        .dkg;
    // Note that although sometimes CUPs have no signatures (e.g. genesis and
    // recovery CUPs) they always have the signer id (the DKG id), which is taken
    // from the high-threshold transcript when we build a genesis/recovery CUP.
    let dkg_id = cup.signature.signer;
    use ic_types::crypto::threshold_sig::ni_dkg::NiDkgTargetSubnet;
    // If the DKG key material was signed by the subnet itself — use it, if not, get
    // the subnet id from the registry.
    match dkg_id.target_subnet {
        NiDkgTargetSubnet::Local => Ok(dkg_id.dealer_subnet),
        // If we hit this case, than the local CUP is a genesis or recovery CUP of an application
        // subnet. We cannot derive the subnet id from it, so we use the registry version of
        // that CUP and the node id of one of the high-threshold committee members, to find
        // out to which subnet this node belongs to.
        NiDkgTargetSubnet::Remote(_) => {
            let node_id = dkg_summary
                .current_transcripts()
                .values()
                .next()
                .ok_or("No current transcript found")?
                .committee
                .get()
                .iter()
                .next()
                .ok_or("No nodes in current transcript committee found")?;
            match registry.get_subnet_id_from_node_id(*node_id, dkg_summary.registry_version) {
                Ok(Some(subnet_id)) => Ok(subnet_id),
                other => Err(format!(
                    "Couldn't get the subnet id from the registry for node {:?}: {:?}",
                    node_id, other
                )),
            }
        }
    }
}

// Checks if the node still belongs to the subnet it was assigned the last
// time. We decide this by checking the subnet membership starting from the
// oldest relevant and ending with the newest relevant registry version of the
// local CUP.
fn should_node_become_unassigned(
    registry: &dyn RegistryClient,
    node_id: NodeId,
    subnet_id: SubnetId,
    cup: &CatchUpPackage,
) -> bool {
    let dkg_summary = &cup
        .content
        .block
        .get_value()
        .payload
        .as_ref()
        .as_summary()
        .dkg;
    let oldest_relevant_version = dkg_summary.get_subnet_membership_version().get();
    // Get the highest registry version relevant for the local CUP.
    let last_relevant_version = dkg_summary.registry_version.get();
    for version in oldest_relevant_version..=last_relevant_version {
        if let Ok(Some(members)) =
            registry.get_node_ids_on_subnet(subnet_id, RegistryVersion::from(version))
        {
            if members.iter().any(|id| id == &node_id) {
                return true;
            }
        }
    }
    false
}
