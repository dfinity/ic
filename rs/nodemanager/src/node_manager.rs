use crate::args::NodeManagerArgs;
use crate::catch_up_package_provider::CatchUpPackageProvider;
use crate::crypto_helper::setup_crypto;
use crate::error::NodeManagerResult;
use crate::firewall::Firewall;
use crate::metrics::NodeManagerMetrics;
use crate::registration::NodeRegistration;
use crate::registry_helper::RegistryHelper;
use crate::release_package::ReleasePackage;
use crate::release_package_provider::ReleasePackageProvider;
use crate::replica_process::ReplicaProcess;
use crate::utils;
use ic_config::registry_client::DataProviderConfig;
use ic_config::{
    firewall::Config as FirewallConfig,
    metrics::{Config as MetricsConfig, Exporter},
    Config,
};
use ic_crypto::utils::get_node_keys_or_generate_if_missing;
use ic_crypto::CryptoComponentForNonReplicaProcess;
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces::{crypto::KeyManager, registry::RegistryClient};
use ic_logger::{info, new_replica_logger, warn, LoggerImpl, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_metrics_exporter::MetricsRuntimeImpl;
use ic_registry_client::nns_registry_replicator::NnsRegistryReplicator;
use ic_registry_common::local_store::{LocalStore, LocalStoreImpl};
use slog_async::AsyncGuard;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub struct NodeManager {
    args: NodeManagerArgs,
    pub logger: ReplicaLogger,
    _async_log_guard: AsyncGuard,
    metrics: Arc<NodeManagerMetrics>,
    _metrics_runtime: MetricsRuntimeImpl,
    _crypto: Arc<dyn CryptoComponentForNonReplicaProcess + Send + Sync>,
    cup_provider: Arc<CatchUpPackageProvider>,
    registry: Arc<RegistryHelper>,
    release_package_provider: Arc<ReleasePackageProvider>,
    firewall_config: Arc<FirewallConfig>,
    pub(crate) nns_registry_replicator: Arc<NnsRegistryReplicator>,
    current_node_manager_hash: String,
    // for tokio 1.0+ we can use `tokio::task::JoinHandle`
    release_package: Option<Arc<std::sync::atomic::AtomicBool>>,
    firewall: Option<Arc<std::sync::atomic::AtomicBool>>,
    replica_process: Option<Arc<Mutex<ReplicaProcess>>>,
}

impl NodeManager {
    pub async fn new(args: NodeManagerArgs) -> Self {
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
        let registry_local_store = Arc::new(LocalStoreImpl::new(local_store_path));

        let crypto = Arc::new(setup_crypto(
            &config.crypto,
            registry.get_registry_client(),
            logger.clone(),
        ));

        let (metrics, _metrics_runtime) = Self::get_metrics(
            metrics_addr,
            &slog_logger,
            &metrics_registry,
            registry.get_registry_client(),
            crypto.clone(),
        );
        let metrics = Arc::new(metrics);

        let firewall = Arc::new(config.firewall.clone());

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

        let cup_provider = Arc::new(CatchUpPackageProvider::new(
            Arc::clone(&registry),
            args.cup_dir.clone(),
            crypto.clone(),
            logger.clone(),
        ));

        let release_package_provider = Arc::new(ReleasePackageProvider::new(
            Arc::clone(&registry),
            args.replica_binary_dir.clone(),
            args.force_replica_binary.clone(),
            logger.clone(),
        ));

        Self {
            args,
            logger,
            _async_log_guard,
            metrics,
            _metrics_runtime,
            _crypto: crypto,
            cup_provider,
            registry,
            release_package_provider,
            firewall_config: firewall,
            nns_registry_replicator,
            current_node_manager_hash,
            release_package: None,
            replica_process: None,
            firewall: None,
        }
    }

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
    pub async fn start(&mut self) -> NodeManagerResult<()> {
        let slog_logger = self.logger.inner_logger.root.clone();
        let replica_process = Arc::new(Mutex::new(ReplicaProcess::new(slog_logger.clone())));
        self.replica_process = Some(replica_process.clone());
        self.release_package = Some(
            ReleasePackage::start(
                Arc::clone(&self.registry),
                replica_process.clone(),
                Arc::clone(&self.release_package_provider),
                Arc::clone(&self.cup_provider),
                self.args.replica_binary_dir.clone(),
                self.args.force_replica_binary.clone(),
                self.args.replica_config_file.clone(),
                self.args
                    .ic_binary_directory
                    .as_ref()
                    .unwrap_or(&PathBuf::from("/tmp"))
                    .clone(),
                self.current_node_manager_hash.clone(),
                self.nns_registry_replicator.clone(),
                self.logger.clone(),
            )
            .await,
        );
        self.firewall = Some(
            Firewall::new(
                Arc::clone(&self.registry),
                Arc::clone(&self.metrics),
                self.firewall_config.as_ref().clone(),
                self.logger.clone(),
            )
            .start(),
        );
        Ok(())
    }

    pub fn spawn_wait_and_restart_replica(&self) {
        let replica_process = self.replica_process.clone().unwrap();
        ReplicaProcess::spawn_wait_and_restart(replica_process);
    }

    pub fn stop_replica(&mut self) {
        // Stop checking for new releases.
        if let Some(release_package) = self.release_package.as_ref() {
            release_package.store(false, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some(firewall) = self.firewall.as_ref() {
            firewall.store(false, std::sync::atomic::Ordering::Relaxed);
        }
        let e = self.replica_process.clone().unwrap().lock().unwrap().stop();
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
            clients_x509_cert: None,
        };

        let metrics_runtime = MetricsRuntimeImpl::new(
            metrics_config,
            metrics_registry.clone(),
            registry_client,
            crypto,
            logger,
        );

        let metrics = NodeManagerMetrics::new(&metrics_registry);

        (metrics, metrics_runtime)
    }
}
