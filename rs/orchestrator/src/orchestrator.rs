use crate::args::OrchestratorArgs;
use crate::catch_up_package_provider::CatchUpPackageProvider;
use crate::crypto_helper::setup_crypto;
use crate::firewall::Firewall;
use crate::metrics::OrchestratorMetrics;
use crate::registration::NodeRegistration;
use crate::registry_helper::RegistryHelper;
use crate::replica_process::ReplicaProcess;
use crate::ssh_access_manager::SshAccessManager;
use crate::upgrade::Upgrade;
use ic_config::metrics::{Config as MetricsConfig, Exporter};
use ic_crypto::utils::get_node_keys_or_generate_if_missing;
use ic_crypto::CryptoComponentForNonReplicaProcess;
use ic_crypto_tls_interfaces::TlsHandshake;
use ic_interfaces::registry::RegistryClient;
use ic_logger::{error, info, new_replica_logger_from_config, warn, ReplicaLogger};
use ic_metrics::MetricsRegistry;
use ic_metrics_exporter::MetricsRuntimeImpl;
use ic_registry_client_helpers::node::NodeRegistry;
use ic_registry_client_helpers::node_operator::NodeOperatorRegistry;
use ic_registry_replicator::RegistryReplicator;
use ic_types::{PrincipalId, ReplicaVersion, SubnetId};
use slog_async::AsyncGuard;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::{convert::TryFrom, time::Duration};
use tokio::{sync::RwLock, task::JoinHandle};

const CHECK_INTERVAL_SECS: Duration = Duration::from_secs(10);

pub struct Orchestrator {
    pub logger: ReplicaLogger,
    _async_log_guard: AsyncGuard,
    _metrics_runtime: MetricsRuntimeImpl,
    upgrade: Option<Upgrade>,
    firewall: Option<Firewall>,
    ssh_access_manager: Option<SshAccessManager>,
    registration: Option<NodeRegistration>,
    // A flag used to communicate to async tasks, that their job is done.
    exit_signal: Arc<RwLock<bool>>,
    // The subnet id of the node.
    subnet_id: Arc<RwLock<Option<SubnetId>>>,
    // Handles of async tasks used to wait for their completion
    task_handles: Vec<JoinHandle<()>>,
}

// Loads the replica version from the file specified as argument on
// orchestrator's start.
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

impl Orchestrator {
    pub async fn new(args: OrchestratorArgs) -> Result<Self, ()> {
        args.create_dirs();
        let metrics_addr = args.get_metrics_addr();
        let config = args.get_ic_config();
        let (_node_pks, node_id) = get_node_keys_or_generate_if_missing(&config.crypto.crypto_root);

        let (logger, _async_log_guard) =
            new_replica_logger_from_config(&config.orchestrator_logger);
        let metrics_registry = MetricsRegistry::global();
        let replica_version = load_version_from_file(&logger, &args.version_file)?;
        info!(
            logger,
            "Orchestrator started: version={}, config={:?}", replica_version, config
        );

        let registry_replicator = Arc::new(RegistryReplicator::new_from_config(
            logger.clone(),
            tokio::runtime::Handle::current(),
            Some(node_id),
            &config,
        ));

        let (nns_urls, nns_pub_key) =
            registry_replicator.parse_registry_access_info_from_config(&config);
        if let Err(err) = registry_replicator
            .fetch_and_start_polling(nns_urls, nns_pub_key)
            .await
        {
            warn!(logger, "{}", err);
        }

        // Filesystem API to local registry copy
        let registry_local_store = registry_replicator.get_local_store();
        // Caches local registry by regularly polling local store
        let registry_client = registry_replicator.get_registry_client();
        // Wrapper to `RegistryClient`
        let registry = Arc::new(RegistryHelper::new(
            node_id,
            registry_client.clone(),
            logger.clone(),
        ));

        let crypto = Arc::new(setup_crypto(
            &config.crypto,
            registry.get_registry_client(),
            logger.clone(),
        ));

        let mut registration = NodeRegistration::new(
            logger.clone(),
            config.clone(),
            Arc::clone(&registry_client),
            node_id,
            Arc::clone(&crypto) as Arc<dyn CryptoComponentForNonReplicaProcess>,
            registry_local_store.clone(),
        );

        if args.enable_provisional_registration {
            // will not return until the node is registered
            registration.register_node().await;
        }

        let slog_logger = logger.inner_logger.root.clone();
        let replica_process = Arc::new(Mutex::new(ReplicaProcess::new(slog_logger.clone())));
        let ic_binary_directory = args
            .ic_binary_directory
            .as_ref()
            .unwrap_or(&PathBuf::from("/tmp"))
            .clone();

        let cup_provider = Arc::new(CatchUpPackageProvider::new(
            Arc::clone(&registry),
            args.cup_dir.clone(),
            crypto.clone(),
            logger.clone(),
        ));

        let upgrade = Some(
            Upgrade::new(
                Arc::clone(&registry),
                replica_process,
                cup_provider,
                replica_version,
                args.replica_config_file.clone(),
                node_id,
                ic_binary_directory,
                registry_replicator,
                args.replica_binary_dir.clone(),
                logger.clone(),
            )
            .await,
        );

        let (metrics, _metrics_runtime) = Self::get_metrics(
            metrics_addr,
            &slog_logger,
            &metrics_registry,
            registry.get_registry_client(),
            crypto.clone(),
        );
        let metrics = Arc::new(metrics);

        let firewall = Some(Firewall::new(
            Arc::clone(&registry),
            Arc::clone(&metrics),
            config.firewall.clone(),
            logger.clone(),
        ));
        let ssh_access_manager = Some(SshAccessManager::new(
            Arc::clone(&registry),
            Arc::clone(&metrics),
            logger.clone(),
        ));
        Ok(Self {
            logger,
            _async_log_guard,
            _metrics_runtime,
            upgrade,
            firewall,
            ssh_access_manager,
            registration: Some(registration),
            exit_signal: Default::default(),
            subnet_id: Default::default(),
            task_handles: Default::default(),
        })
    }

    /// Starts three asynchronous tasks:
    ///
    /// 1. One that constantly monitors for a new CUP pointing to a newer
    /// replica version and executes the upgrade to this version if such a
    /// CUP was found.
    ///
    /// 2. Second task is doing two things sequentially. First, it  monitors the
    /// registry for new SSH readonly keys and deploys the detected keys
    /// into OS. Second, it monitors the registry for new data centers. If a
    /// new data center is added, orchestrator will generate a new firewall
    /// configuration allowing access from the IP range specified in the DC
    /// record.
    ///
    /// 3. Third task tries to update the registry with the iDKG key. Eventually
    /// once all replicas are updated this functionality should be removed,
    /// but the plumbing of the adding key mechanism will remain.
    pub fn spawn_tasks(&mut self) {
        async fn upgrade_checks(
            maybe_subnet_id: Arc<RwLock<Option<SubnetId>>>,
            mut upgrade: Upgrade,
            exit_signal: Arc<RwLock<bool>>,
            log: ReplicaLogger,
        ) {
            // This timeout is a last resort trying to revive the upgrade monitoring
            // in case it gets stuck in an unexpected situation for longer than 30 minutes.
            let timeout = Duration::from_secs(60 * 15);
            while !*exit_signal.read().await {
                match tokio::time::timeout(timeout, upgrade.check()).await {
                    Ok(Ok(val)) => *maybe_subnet_id.write().await = val,
                    e => warn!(log, "Check for upgrade failed: {:?}", e),
                };
                tokio::time::sleep(CHECK_INTERVAL_SECS).await;
            }
            info!(log, "Shut down the upgrade loop");
            if let Err(e) = upgrade.stop_replica() {
                warn!(log, "{}", e);
            }
            info!(log, "Shut down the replica process");
        }

        async fn ssh_key_and_firewall_rules_checks(
            maybe_subnet_id: Arc<RwLock<Option<SubnetId>>>,
            mut ssh_access_manager: SshAccessManager,
            mut firewall: Firewall,
            exit_signal: Arc<RwLock<bool>>,
            log: ReplicaLogger,
        ) {
            while !*exit_signal.read().await {
                // Check if new SSH keys need to be deployed
                ssh_access_manager
                    .check_for_keyset_changes(*maybe_subnet_id.read().await)
                    .await;
                // Check and update the firewall rules
                firewall.check_and_update();
                tokio::time::sleep(CHECK_INTERVAL_SECS).await;
            }
            info!(log, "Shut down the ssh keys & firewall monitoring loop");
        }
        async fn update_keys_in_registry(
            log: ReplicaLogger,
            exit_signal: Arc<RwLock<bool>>,
            registration: NodeRegistration,
        ) {
            while !*exit_signal.read().await {
                if registration
                    .check_additional_key_registered_otherwise_register()
                    .await
                {
                    // additional key was successfully registered
                    break;
                };
                tokio::time::sleep(CHECK_INTERVAL_SECS).await;
            }
            info!(log, "Shut down update keys in registration loop");
        }

        if let Some(upgrade) = self.upgrade.take() {
            info!(self.logger, "Spawning the upgrade loop");
            self.task_handles.push(tokio::spawn(upgrade_checks(
                Arc::clone(&self.subnet_id),
                upgrade,
                Arc::clone(&self.exit_signal),
                self.logger.clone(),
            )));
        }

        if let (Some(ssh), Some(firewall)) = (self.ssh_access_manager.take(), self.firewall.take())
        {
            info!(
                self.logger,
                "Spawning the ssh-key and firewall rules check loop"
            );
            self.task_handles
                .push(tokio::spawn(ssh_key_and_firewall_rules_checks(
                    Arc::clone(&self.subnet_id),
                    ssh,
                    firewall,
                    Arc::clone(&self.exit_signal),
                    self.logger.clone(),
                )));
        }

        if let Some(registration) = self.registration.take() {
            info!(self.logger, "Spawning the additional key registration loop");
            self.task_handles.push(tokio::spawn(update_keys_in_registry(
                self.logger.clone(),
                Arc::clone(&self.exit_signal),
                registration,
            )));
        }
    }

    /// Print the replica's current node ID.
    pub fn node_id(args: OrchestratorArgs) {
        let config = args.get_ic_config();
        let (_node_pks, node_id) = get_node_keys_or_generate_if_missing(&config.crypto.crypto_root);

        println!("{}", node_id);
    }

    /// Print the DC ID where the current replica is located.
    pub fn dc_id(args: OrchestratorArgs) {
        let config = args.get_ic_config();
        let (_node_pks, node_id) = get_node_keys_or_generate_if_missing(&config.crypto.crypto_root);

        let (logger, _async_log_guard) =
            new_replica_logger_from_config(&config.orchestrator_logger);

        let registry_replicator = Arc::new(RegistryReplicator::new_from_config(
            logger.clone(),
            tokio::runtime::Handle::current(),
            Some(node_id),
            &config,
        ));
        let registry_client = registry_replicator.get_registry_client();
        let registry = Arc::new(RegistryHelper::new(
            node_id,
            registry_client.clone(),
            logger,
        ));

        let registry_version = registry.get_latest_version();
        let node_record = registry_client
            .get_transport_info(node_id, registry_version)
            .ok()
            .flatten();
        let node_operator_id =
            node_record.and_then(|v| PrincipalId::try_from(v.node_operator_id).ok());

        let node_operator_record = node_operator_id.and_then(|id| {
            registry_client
                .get_node_operator_record(id, registry_version)
                .ok()
                .flatten()
        });
        let dc_id = node_operator_record.map(|v| v.dc_id);

        if let Some(dc_id) = dc_id {
            println!("{}", dc_id);
        }
    }

    /// Shuts down the orchestrator: stops async tasks and the replica process
    pub async fn shutdown(self) {
        info!(self.logger, "Shutting down orchestrator...");
        // Communicate to async tasks that the y should exit.
        *self.exit_signal.write().await = true;
        // Wait until tasks are done.
        for handle in self.task_handles {
            let _ = handle.await;
        }
        info!(self.logger, "Orchestrator shut down");
    }

    // Construct a `OrchestratorMetrics` and its `MetricsRuntimeImpl`. If this
    // `MetricsRuntimeImpl` is dropped, metrics will no longer be
    // collected.
    fn get_metrics(
        metrics_addr: SocketAddr,
        logger: &slog::Logger,
        metrics_registry: &MetricsRegistry,
        registry_client: Arc<dyn RegistryClient>,
        crypto: Arc<dyn TlsHandshake + Send + Sync>,
    ) -> (OrchestratorMetrics, MetricsRuntimeImpl) {
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

        let metrics = OrchestratorMetrics::new(metrics_registry);

        (metrics, metrics_runtime)
    }
}
