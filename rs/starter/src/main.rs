//! The ic-starter provides a minimal functioning environment for a single
//! replica to be used with the SDK.
//!
//! Minimal example use, from the rs/ directory:
//!     cargo run --bin ic-starter
//! This will:
//!   - compile the replica with the default cargo build options
//!   - start the built replica, listening on port 8080
//!
//! Run replica in release mode:
//!     cargo run --bin ic-starter --release
//!
//! Another more complete example with additional arguments:
//!     cargo run --bin ic-starter -- --state-dir=/some/dir \
//!           --log-level info --metrics-addr localhost:18080
//! That:
//!   - starts the replica in debug build
//!   - uses `/some/dir` to store state
//!   - sets the log level to info
//!   - serves metrics at localhost:18080 instead of dumping them at stdout

use anyhow::Result;
use clap::Parser;
use ic_config::{
    adapters::AdaptersConfig,
    artifact_pool::ArtifactPoolTomlConfig,
    crypto::CryptoConfig,
    embedders::Config as EmbeddersConfig,
    embedders::FeatureFlags,
    execution_environment::Config as HypervisorConfig,
    flag_status::FlagStatus,
    http_handler::Config as HttpHandlerConfig,
    logger::Config as LoggerConfig,
    metrics::{Config as MetricsConfig, Exporter},
    registry_client::Config as RegistryClientConfig,
    state_manager::Config as StateManagerConfig,
    transport::TransportConfig,
    ConfigOptional as ReplicaConfig,
};
use ic_logger::{info, new_replica_logger_from_config};
use ic_management_canister_types::EcdsaKeyId;
use ic_prep_lib::{
    internet_computer::{IcConfig, TopologyConfig},
    node::{NodeConfiguration, NodeIndex},
    subnet_configuration::{SubnetConfig, SubnetRunningState},
};
use ic_protobuf::registry::subnet::v1::{ChainKeyConfig, EcdsaConfig};
use ic_registry_provisional_whitelist::ProvisionalWhitelist;
use ic_registry_subnet_features::SubnetFeatures;
use ic_registry_subnet_type::SubnetType;
use ic_types::{Height, ReplicaVersion};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    time::Duration,
};
use std::{io, os::unix::process::CommandExt, path::PathBuf, process::Command, str::FromStr};
use tempfile::TempDir;

const NODE_INDEX: NodeIndex = 100;
const SUBNET_ID: u64 = 0;

fn main() -> Result<()> {
    let config = CliArgs::parse().validate()?;
    let logger_config = LoggerConfig {
        level: config.log_level,
        ..LoggerConfig::default()
    };
    let (log, _async_log_guard) = new_replica_logger_from_config(&logger_config);

    info!(log, "ic-starter. Configuration: {:?}", config);
    let config_path = config.state_dir.join("ic.json5");

    info!(log, "Initialize replica configuration {:?}", config_path);

    let replica_config = config.build_replica_config();

    // assemble config
    let config_json = serde_json::to_string(&replica_config).unwrap();
    std::fs::write(config_path.clone(), config_json.into_bytes()).unwrap();

    if !config.registry_local_store_path.exists() {
        // assemble registry.json
        // At the moment, this always regenerates the node key.
        // TODO: Only regenerate if necessary, depends on CRP-359

        let mut subnet_nodes: BTreeMap<NodeIndex, NodeConfiguration> = BTreeMap::new();
        subnet_nodes.insert(
            NODE_INDEX,
            NodeConfiguration {
                xnet_api: SocketAddr::from_str("127.0.0.1:0").unwrap(),
                public_api: config.http_listen_addr,
                node_operator_principal_id: None,
                secret_key_store: None,
            },
        );

        let ecdsa_config = config.ecdsa_keyid.clone().map(|key_id| EcdsaConfig {
            quadruples_to_create_in_advance: 1,
            key_ids: vec![(&key_id).into()],
            max_queue_size: 64,
            signature_request_timeout_ns: None,
            idkg_key_rotation_period_ms: None,
        });

        let chain_key_config = ecdsa_config.clone().map(ChainKeyConfig::from);

        let mut topology_config = TopologyConfig::default();
        topology_config.insert_subnet(
            SUBNET_ID,
            SubnetConfig::new(
                SUBNET_ID,
                subnet_nodes,
                config.replica_version.clone(),
                None,
                None,
                None,
                config.unit_delay,
                config.initial_notary_delay,
                config.dkg_interval_length,
                None,
                config.subnet_type,
                None,
                None,
                None,
                Some(config.subnet_features),
                ecdsa_config,
                chain_key_config,
                None,
                vec![],
                vec![],
                SubnetRunningState::default(),
                None,
            ),
        );

        // N.B. it is safe to generate subnet records here, we only skip this
        // step for a specific deployment case in ic-prep: when we want to deploy
        // nodes without assigning them to subnets

        let mut ic_config = IcConfig::new(
            /* target_dir= */ config.state_dir.as_path(),
            topology_config,
            config.replica_version.clone(),
            /* generate_subnet_records= */ true, // see note above
            /* nns_subnet_index= */ Some(0),
            /* release_package_url= */ None,
            /* release_package_sha256_hex */ None,
            config.provisional_whitelist,
            None,
            None,
            /* ssh_readonly_access_to_unassigned_nodes */ vec![],
        );

        ic_config.set_use_specified_ids_allocation_range(config.use_specified_ids_allocation_range);

        ic_config.initialize()?;
    }

    let (mut base_cmd, use_cargo) = match config.replica_path {
        Some(f) => (Command::new(f), false),
        None => (Command::new(config.cargo_bin), true),
    };

    // If ic-starter is built in release mode then, by default, start replica
    // in release mode as well.
    let mut cargo_opts = config.cargo_opts;
    if !cfg!(debug_assertions) && !cargo_opts.contains("--release") {
        cargo_opts.push_str("--release")
    };

    let cmd = if use_cargo {
        base_cmd
            .arg("run")
            .arg("--bin")
            .arg("replica")
            .args(cargo_opts.split_whitespace())
            .arg("--")
    } else {
        &mut base_cmd
    };
    let cmd = cmd
        .arg("--replica-version")
        .arg(config.replica_version.to_string())
        .arg("--config-file")
        .args([config_path.to_str().unwrap()]);
    info!(log, "Executing {:?}", cmd);
    cmd.exec();

    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Parser)]
#[clap(name = "ic-starter", about = "Starter.", version)]
struct CliArgs {
    /// Path the to replica binary.
    ///
    /// The replica binary will be built if not provided. In this case, it is
    /// expected that a config will be found for '--bin replica'. In other
    /// words, it is expected that the starter is invoked from the rs/
    /// directory.
    #[clap(long = "replica-path", parse(from_os_str))]
    replica_path: Option<PathBuf>,

    /// Version of the replica binary.
    #[clap(long, parse(try_from_str = ReplicaVersion::try_from))]
    replica_version: Option<ReplicaVersion>,

    /// Path to the cargo binary. Not optional because there is a default value.
    ///
    /// Unused if --replica-path is present
    #[clap(long = "cargo", default_value = "cargo")]
    cargo_bin: String,

    /// Options to pass to cargo, such as "--release". Not optional because
    /// there is a default value.
    ///
    /// Several options can be passed, with whitespaces inside the value. For
    /// instance: cargo run ic-starter -- '--cargo-opts=--release --quiet'
    ///
    /// Unused if --replica-path is present
    #[clap(long = "cargo-opts", default_value = "")]
    cargo_opts: String,

    /// Path to the directory containing all state for this replica. (default: a
    /// temp directory that will be deleted immediately when the replica
    /// stops).
    #[clap(long = "state-dir", parse(from_os_str))]
    state_dir: Option<PathBuf>,

    /// The http port of the public API.
    ///
    /// If not specified, and if --http-port-file is empty, then 8080 will be
    /// used.
    ///
    /// This argument is incompatible with --http-port-file.
    #[clap(long = "http-port")]
    http_port: Option<u16>,

    /// The http listening address of the public API.
    ///
    /// If not specified, and if --http-port-file is empty, then 127.0.0.1:8080
    /// will be used.
    #[clap(long = "http-listen-addr")]
    http_listen_addr: Option<SocketAddr>,

    /// The file where the chosen port of the public api will be written to.
    /// When this option is used, a free port will be chosen by the replica
    /// at start time.
    ///
    /// This argument is incompatible with --http-port.
    #[clap(long = "http-port-file", parse(from_os_str))]
    http_port_file: Option<PathBuf>,

    /// Arg to control whitelist for creating funds which is either set to "*"
    /// or "".
    #[clap(short = 'c', long = "create-funds-whitelist")]
    provisional_whitelist: Option<String>,

    /// Run replica and ic-starter with the provided log level. Default is Warning
    #[clap(long = "log-level",
                possible_values = &["critical", "error", "warning", "info", "debug", "trace"],
                ignore_case = true)]
    log_level: Option<String>,

    /// Debug overrides to show debug logs for certain components.
    #[clap(long = "debug-overrides", multiple_values(true))]
    debug_overrides: Vec<String>,

    /// Metrics port. Default is None, i.e. periodically dump metrics on stdout.
    #[clap(long = "metrics-port")]
    metrics_port: Option<u16>,

    /// Metrics address. Use this in preference to metrics-port
    #[clap(long = "metrics-addr")]
    metrics_addr: Option<SocketAddr>,

    /// Unit delay for blockmaker (in milliseconds).
    /// If running integration tests locally (e.g. ic-ref-test),
    /// setting this to 100ms results in faster execution (and higher
    /// CPU consumption).
    #[clap(long = "unit-delay-millis")]
    unit_delay_millis: Option<u64>,

    /// Initial delay for notary (in milliseconds).
    /// If running integration tests locally (e.g. ic-ref-test),
    /// setting this to 100ms results in faster execution (and higher
    /// CPU consumption).
    #[clap(long = "initial-notary-delay-millis")]
    initial_notary_delay_millis: Option<u64>,

    /// DKG interval length (in number of blocks).
    #[clap(long = "dkg-interval-length")]
    dkg_interval_length: Option<u64>,

    /// The backend DB used by Consensus, can be rocksdb or lmdb.
    #[clap(long = "consensus-pool-backend",
                possible_values = &["lmdb", "rocksdb"])]
    consensus_pool_backend: Option<String>,

    /// Subnet features
    #[clap(long = "subnet-features",
        possible_values = &[
            "canister_sandboxing",
            "http_requests",
            "bitcoin_testnet",
            "bitcoin_testnet_syncing",
            "bitcoin_testnet_paused",
            "bitcoin_mainnet",
            "bitcoin_mainnet_syncing",
            "bitcoin_mainnet_paused",
            "bitcoin_regtest",
            "bitcoin_regtest_syncing",
            "bitcoin_regtest_paused",
        ],
        multiple_values(true))]
    subnet_features: Vec<String>,

    /// Enable ecdsa signature by assigning the given key id a freshly generated key.
    #[clap(long = "ecdsa-keyid")]
    ecdsa_keyid: Option<String>,

    /// Subnet type
    #[clap(long = "subnet-type",
                possible_values = &["application", "verified_application", "system"])]
    subnet_type: Option<String>,

    /// Unix Domain Socket for Bitcoin testnet
    #[clap(long = "bitcoin-testnet-uds-path")]
    bitcoin_testnet_uds_path: Option<PathBuf>,

    /// Unix Domain Socket for canister http adapter
    #[clap(long = "canister-http-uds-path")]
    canister_http_uds_path: Option<PathBuf>,

    /// Whether or not to assign canister ID allocation range for specified IDs to subnet.
    /// Used only for local replicas.
    #[clap(long = "use-specified-ids-allocation-range")]
    use_specified_ids_allocation_range: bool,
}

impl CliArgs {
    fn validate(self) -> io::Result<ValidatedConfig> {
        let replica_version = self.replica_version.unwrap_or_default();
        // check whether replica path exists, if it is specified.
        let replica_path = self.replica_path;
        if let Some(f) = &replica_path {
            if !f.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Replica not found at: {:?}", replica_path),
                ));
            }
        }
        let cargo_bin = self.cargo_bin;
        let cargo_opts = self.cargo_opts;

        // check whether state_dir exists; create it if needed.
        let (state_dir, _state_dir_holder) = if self.state_dir.is_none() {
            let maybe_dir = tempfile::tempdir();
            if maybe_dir.is_err() {
                return Err(io::Error::new(
                    maybe_dir.err().unwrap().kind(),
                    "Could not create a temp dir.",
                ));
            }
            let dir = maybe_dir.unwrap();
            let path = dir.path().to_path_buf();
            (path, Some(dir))
        } else {
            (self.state_dir.unwrap(), None)
        };
        if !state_dir.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Replica state directory not found at: {:?}", state_dir),
            ));
        }

        // XXX: Must be kept in sync with SubnetConfiguration implementation
        let node_dir = state_dir.join(format!("node-{}", NODE_INDEX));

        // check whether state_dir is writeable
        if state_dir.metadata()?.permissions().readonly() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("Cannot write state directory at: {:?}", state_dir),
            ));
        }

        let (http_listen_addr, http_port_file) =
            match (self.http_port, self.http_listen_addr, self.http_port_file) {
                (None, None, None) => Ok((
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080),
                    None,
                )),
                (None, None, Some(path)) => Ok((
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
                    Some(path),
                )),
                (None, Some(listen_addr), None) => Ok((listen_addr, None)),
                (None, Some(listen_addr), Some(path)) => Ok((listen_addr, Some(path))),
                (Some(port), None, None) => Ok((
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
                    None,
                )),
                (Some(_), None, Some(_)) => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Arguments --http-port and --http-port-file are incompatible.",
                )),
                (Some(_), Some(_), _) => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Arguments --http-port and --http-listen-addr are incompatible",
                )),
            }?;

        // check whether parent directory of port_file exists
        if let Some(http_port_file) = &http_port_file {
            if http_port_file
                .parent()
                .and_then(|p| if !p.is_dir() { None } else { Some(p) })
                .is_none()
            {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "Parent directory of http_port_file not found at: {:?}",
                        replica_path
                    ),
                ));
            }
        }

        let metrics_port = self.metrics_port;
        let mut metrics_addr = self.metrics_addr;

        if metrics_addr.is_some() && metrics_port.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "can't pass --metrics-addr and --metrics-port at the same time",
            ));
        }

        if let Some(port) = metrics_port {
            println!("--metrics-port is deprecated, use --metrics-addr instead");
            // If only --metrics-port is given then fallback to previous behaviour
            // of listening on 0.0.0.0. Note that this will trigger warning
            // popups on macOS.
            metrics_addr =
                Some(SocketAddrV4::new("0.0.0.0".parse().expect("can't fail"), port).into());
        }

        let log_level = match self.log_level {
            Some(log_level) => match log_level.to_lowercase().as_str() {
                // According to the principle of least surprise, accept also a
                // few alternative log level names
                "critical" => slog::Level::Critical,
                "error" => slog::Level::Error,
                "warning" => slog::Level::Warning,
                "info" => slog::Level::Info,
                "debug" => slog::Level::Debug,
                "trace" => slog::Level::Trace,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("Invalid Log level provided: {}", log_level),
                    ))
                }
            },
            None => slog::Level::Warning,
        };

        let artifact_pool_dir = node_dir.join("ic_consensus_pool");
        let crypto_root = node_dir.join("crypto");
        let state_manager_root = node_dir.join("state");
        let registry_local_store_path = state_dir.join("ic_registry_local_store");

        let provisional_whitelist = match self.provisional_whitelist.unwrap_or_default().as_str() {
            "*" => Some(ProvisionalWhitelist::All),
            "" => None,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Whitelist can only be '*' or ''".to_string(),
                ))
            }
        };

        let unit_delay = self.unit_delay_millis.map(Duration::from_millis);
        let initial_notary_delay = self.initial_notary_delay_millis.map(Duration::from_millis);

        let subnet_type = match self.subnet_type.as_deref() {
            Some("application") => SubnetType::Application,
            Some("verified_application") => SubnetType::VerifiedApplication,
            Some("system") | None => SubnetType::System,
            Some(s) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid subnet_type: {}", s),
                ))
            }
        };

        let ecdsa_keyid = self
            .ecdsa_keyid
            .as_ref()
            .map(|s| EcdsaKeyId::from_str(s))
            .transpose()
            .map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Invalid ecdsa_keyid: {}", err),
                )
            })?;

        Ok(ValidatedConfig {
            replica_path,
            replica_version,
            log_level,
            debug_overrides: self.debug_overrides.clone(),
            cargo_bin,
            cargo_opts,
            state_dir,
            http_listen_addr,
            http_port_file,
            metrics_addr,
            provisional_whitelist,
            artifact_pool_dir,
            crypto_root,
            state_manager_root,
            registry_local_store_path,
            _state_dir_holder,
            unit_delay,
            initial_notary_delay,
            dkg_interval_length: self.dkg_interval_length.map(Height::from),
            consensus_pool_backend: self.consensus_pool_backend,
            subnet_features: to_subnet_features(&self.subnet_features),
            ecdsa_keyid,
            subnet_type,
            bitcoin_testnet_uds_path: self.bitcoin_testnet_uds_path,
            https_outcalls_uds_path: self.canister_http_uds_path,
            use_specified_ids_allocation_range: self.use_specified_ids_allocation_range,
        })
    }
}

fn to_subnet_features(features: &[String]) -> SubnetFeatures {
    let canister_sandboxing = features.iter().any(|s| s.as_str() == "canister_sandboxing");
    let http_requests = features.iter().any(|s| s.as_str() == "http_requests");
    SubnetFeatures {
        canister_sandboxing,
        http_requests,
        ..Default::default()
    }
}

#[derive(Debug)]
struct ValidatedConfig {
    replica_path: Option<PathBuf>,
    replica_version: ReplicaVersion,
    log_level: slog::Level,
    debug_overrides: Vec<String>,
    cargo_bin: String,
    cargo_opts: String,
    state_dir: PathBuf,
    http_listen_addr: SocketAddr,
    http_port_file: Option<PathBuf>,
    metrics_addr: Option<SocketAddr>,
    provisional_whitelist: Option<ProvisionalWhitelist>,
    artifact_pool_dir: PathBuf,
    crypto_root: PathBuf,
    state_manager_root: PathBuf,
    registry_local_store_path: PathBuf,
    unit_delay: Option<Duration>,
    initial_notary_delay: Option<Duration>,
    dkg_interval_length: Option<Height>,
    consensus_pool_backend: Option<String>,
    subnet_features: SubnetFeatures,
    ecdsa_keyid: Option<EcdsaKeyId>,
    subnet_type: SubnetType,
    bitcoin_testnet_uds_path: Option<PathBuf>,
    https_outcalls_uds_path: Option<PathBuf>,
    use_specified_ids_allocation_range: bool,

    // Not intended to ever be read: role is to keep the temp dir from being deleted.
    _state_dir_holder: Option<TempDir>,
}

impl ValidatedConfig {
    fn build_replica_config(self: &ValidatedConfig) -> ReplicaConfig {
        let state_manager = Some(StateManagerConfig::new(self.state_manager_root.clone()));
        let http_handler = Some(HttpHandlerConfig {
            listen_addr: self.http_listen_addr,
            port_file_path: self.http_port_file.clone(),
            ..Default::default()
        });
        let metrics = self.metrics_addr.map(|metrics_addr| MetricsConfig {
            exporter: Exporter::Http(metrics_addr),
            ..Default::default()
        });

        let mut artifact_pool_cfg =
            ArtifactPoolTomlConfig::new(self.artifact_pool_dir.clone(), None);
        // artifact_pool.rs picks "lmdb" if None here
        artifact_pool_cfg.consensus_pool_backend = self.consensus_pool_backend.clone();
        let artifact_pool = Some(artifact_pool_cfg);

        let crypto = Some(CryptoConfig::new(self.crypto_root.clone()));
        let registry_client = Some(RegistryClientConfig {
            local_store: self.registry_local_store_path.clone(),
        });
        let logger_config = LoggerConfig {
            node_id: NODE_INDEX,
            level: self.log_level,
            debug_overrides: self.debug_overrides.clone(),
            ..LoggerConfig::default()
        };
        let logger = Some(logger_config);

        let transport = Some(TransportConfig {
            node_ip: "0.0.0.0".to_string(),
            listening_port: 0,
            send_queue_size: 1024,
            ..Default::default()
        });

        let hypervisor_config = HypervisorConfig {
            canister_sandboxing_flag: if self.subnet_features.canister_sandboxing {
                FlagStatus::Enabled
            } else {
                FlagStatus::Disabled
            },
            embedders_config: EmbeddersConfig {
                feature_flags: FeatureFlags {
                    rate_limiting_of_debug_prints: FlagStatus::Disabled,
                    canister_logging: FlagStatus::Enabled,
                    ..FeatureFlags::default()
                },
                ..EmbeddersConfig::default()
            },
            rate_limiting_of_heap_delta: FlagStatus::Disabled,
            rate_limiting_of_instructions: FlagStatus::Disabled,
            composite_queries: FlagStatus::Enabled,
            wasm_chunk_store: FlagStatus::Enabled,
            query_stats_aggregation: FlagStatus::Enabled,
            query_stats_epoch_length: 60,
            ..HypervisorConfig::default()
        };

        let hypervisor = Some(hypervisor_config);

        let adapters_config = Some(AdaptersConfig {
            bitcoin_testnet_uds_path: self.bitcoin_testnet_uds_path.clone(),
            https_outcalls_uds_path: self.https_outcalls_uds_path.clone(),
            ..AdaptersConfig::default()
        });

        ReplicaConfig {
            registry_client,
            transport,
            state_manager,
            hypervisor,
            http_handler,
            metrics,
            artifact_pool,
            crypto,
            logger,
            adapters_config,
            ..ReplicaConfig::default()
        }
    }
}
