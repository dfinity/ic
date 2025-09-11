use clap::Parser;
use ic_crypto_utils_threshold_sig_der::{
    parse_threshold_sig_key, parse_threshold_sig_key_from_der,
};
use ic_nns_constants::{GOVERNANCE_CANISTER_ID, LEDGER_CANISTER_ID};
use ic_rosetta_api::request_handler::RosettaRequestHandler;
use ic_rosetta_api::rosetta_server::{RosettaApiServer, RosettaApiServerOpt};
use ic_rosetta_api::{DEFAULT_BLOCKCHAIN, DEFAULT_TOKEN_SYMBOL, ledger_client};
use ic_types::crypto::threshold_sig::ThresholdSigPublicKey;
use ic_types::{CanisterId, PrincipalId};
use rosetta_core::metrics::RosettaMetrics;
use std::{path::Path, path::PathBuf, str::FromStr, sync::Arc};
use tracing::level_filters::LevelFilter;
use tracing::{Level, error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::filter::FilterExt;
use tracing_subscriber::filter::FilterFn;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, Registry};
use url::Url;

const TEST_LEDGER_CANISTER_ID: &str = "xafvr-biaaa-aaaai-aql5q-cai";
const TEST_TOKEN_SYMBOL: &str = "TESTICP";

#[derive(Debug, Clone, clap::ValueEnum, PartialEq, Default)]
enum Environment {
    #[clap(help = "Production ledger canister on mainnet")]
    Production,
    #[clap(help = "Test ledger canister on mainnet")]
    Test,
    #[clap(name = "deprecated-testnet", help = "Testnet environment (deprecated)")]
    #[default]
    DeprecatedTestnet,
}

#[derive(Debug, Parser)]
#[clap(next_help_heading = "Server Configuration")]
struct ServerConfig {
    #[clap(short = 'a', long = "address", default_value = "0.0.0.0")]
    address: String,
    /// The listen port of Rosetta. If not set then the port used will be 8081 unless --port-file is
    /// defined in which case a random port is used.
    #[clap(short = 'p', long = "port")]
    port: Option<u16>,
    /// File where the port will be written. Useful when the port is set to 0 because a random port will be picked.
    #[clap(short = 'P', long = "port-file")]
    port_file: Option<PathBuf>,
}

#[derive(Debug, Parser)]
#[clap(next_help_heading = "Storage Configuration")]
struct StorageConfig {
    /// Supported options: sqlite, sqlite-in-memory
    #[clap(long = "store-type", default_value = "sqlite")]
    store_type: String,
    #[clap(long = "store-location", default_value = "/data")]
    location: PathBuf,
    #[clap(long = "store-max-blocks")]
    max_blocks: Option<u64>,
    /// Enable optimization for search/transactions by creating additional indexes
    #[clap(
        long = "optimize-search-indexes",
        help = "Create additional indexes to optimize transaction search performance. May increase the database size by ~30%."
    )]
    optimize_indexes: bool,
}

#[derive(Debug, Parser)]
#[clap(next_help_heading = "Network Configuration")]
struct NetworkConfig {
    /// The URL of the replica to connect to.
    #[clap(long = "ic-url")]
    ic_url: Option<String>,
    #[clap(long = "root-key")]
    root_key: Option<PathBuf>,
}

#[derive(Debug)]
struct ParsedNetworkConfig {
    pub ic_url: Url,
    pub root_key: Option<ThresholdSigPublicKey>,
}

impl ParsedNetworkConfig {
    fn from_config(config: NetworkConfig, environment: &Environment) -> Result<Self, String> {
        const DEPRECATED_TESTNET_URL: &str = "https://exchanges.testnet.dfinity.network";
        const MAINNET_URL: &str = "https://ic0.app";
        const MAINNET_ROOT_KEY: &str = r#"MIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAIFMDm7HH6tYOwi9gTc8JVw8NxsuhIY8mKTx4It0I10U+12cDNVG2WhfkToMCyzFNBWDv0tDkuRn25bWW5u0y3FxEvhHLg1aTRRQX/10hLASkQkcX4e5iINGP5gJGguqrg=="#;

        let url_str = match &config.ic_url {
            Some(url_str) => url_str.as_str(),
            None => match environment {
                Environment::DeprecatedTestnet => DEPRECATED_TESTNET_URL,
                Environment::Production | Environment::Test => MAINNET_URL,
            },
        };
        let ic_url = Url::parse(url_str).map_err(|e| format!("Unable to parse --ic-url: {e}"))?;

        let root_key = match config.root_key {
            Some(root_key_path) => Some(
                parse_threshold_sig_key(root_key_path.as_path())
                    .map_err(|e| format!("Unable to parse root key from file: {e}"))?,
            ),
            None => {
                match environment {
                    Environment::Production | Environment::Test => {
                        // The mainnet root key
                        let decoded = base64::decode(MAINNET_ROOT_KEY).unwrap();
                        Some(parse_threshold_sig_key_from_der(&decoded).unwrap())
                    }
                    Environment::DeprecatedTestnet => None,
                }
            }
        };

        Ok(Self { ic_url, root_key })
    }
}

#[derive(Debug, Parser)]
#[clap(next_help_heading = "Canister Configuration")]
struct CanisterConfig {
    /// Id of the ICP ledger canister.
    #[clap(short = 'c', long = "canister-id")]
    ledger_canister_id: Option<String>,
    #[clap(short = 't', long = "token-symbol")]
    token_symbol: Option<String>,
    /// Id of the governance canister to use for neuron management.
    #[clap(short = 'g', long = "governance-canister-id")]
    governance_canister_id: Option<String>,
}

#[derive(Debug)]
struct ParsedCanisterConfig {
    pub ledger_canister_id: CanisterId,
    pub token_symbol: String,
    pub governance_canister_id: CanisterId,
}

impl ParsedCanisterConfig {
    fn from_config(config: CanisterConfig, environment: &Environment) -> Result<Self, String> {
        // Apply environment preset defaults when no explicit value provided
        let ledger_canister_id = match config.ledger_canister_id {
            Some(explicit_value) => CanisterId::unchecked_from_principal(
                PrincipalId::from_str(&explicit_value)
                    .map_err(|e| format!("Invalid ledger canister ID '{explicit_value}': {e}"))?,
            ),
            None => match environment {
                Environment::Test => CanisterId::unchecked_from_principal(
                    PrincipalId::from_str(TEST_LEDGER_CANISTER_ID).map_err(|e| {
                        format!("Invalid test ledger canister ID '{TEST_LEDGER_CANISTER_ID}': {e}")
                    })?,
                ),
                Environment::Production | Environment::DeprecatedTestnet => LEDGER_CANISTER_ID,
            },
        };

        let token_symbol = match config.token_symbol {
            Some(explicit_value) => explicit_value,
            None => match environment {
                Environment::Test => TEST_TOKEN_SYMBOL.to_string(),
                Environment::Production | Environment::DeprecatedTestnet => {
                    DEFAULT_TOKEN_SYMBOL.to_string()
                }
            },
        };

        let governance_canister_id = match config.governance_canister_id {
            Some(explicit_value) => CanisterId::unchecked_from_principal(
                PrincipalId::from_str(&explicit_value).map_err(|e| {
                    format!("Invalid governance canister ID '{explicit_value}': {e}")
                })?,
            ),
            None => GOVERNANCE_CANISTER_ID,
        };

        Ok(Self {
            ledger_canister_id,
            token_symbol,
            governance_canister_id,
        })
    }
}

#[derive(Debug, Parser)]
#[clap(version)]
struct Opt {
    #[clap(
        short = 'e',
        long = "environment",
        default_value = "deprecated-testnet",
        help = "Environment preset that configures network and canister settings."
    )]
    environment: Environment,

    #[clap(flatten)]
    server: ServerConfig,

    #[clap(flatten)]
    storage: StorageConfig,

    #[clap(flatten)]
    network: NetworkConfig,

    #[clap(flatten)]
    canister: CanisterConfig,

    #[clap(short = 'l', long = "log-config-file")]
    log_config_file: Option<PathBuf>,
    #[clap(short = 'L', long = "log-level", default_value = "INFO")]
    log_level: Level,
    #[clap(long = "exit-on-sync")]
    exit_on_sync: bool,
    #[clap(long = "offline")]
    offline: bool,
    #[clap(long = "mainnet", help = "Connect to the Internet Computer Mainnet")]
    mainnet: bool,
    /// The name of the blockchain reported in the network identifier.
    #[clap(long = "blockchain", default_value = DEFAULT_BLOCKCHAIN)]
    blockchain: String,
    #[clap(long = "not-whitelisted")]
    not_whitelisted: bool,
    #[clap(long = "expose-metrics")]
    expose_metrics: bool,
    #[clap(
        long = "watchdog-timeout-seconds",
        default_value = "60",
        help = "Timeout in seconds for sync watchdog"
    )]
    watchdog_timeout_seconds: u64,

    #[cfg(feature = "rosetta-blocks")]
    #[clap(long = "enable-rosetta-blocks")]
    enable_rosetta_blocks: bool,
}

fn init_logging(level: Level) -> std::io::Result<WorkerGuard> {
    std::fs::create_dir_all("log")?;

    // stdout
    fn rosetta_filter(module: &str) -> bool {
        module.starts_with("ic_rosetta_api")
            || module.starts_with("ic_ledger_canister_blocks_synchronizer")
            || module.starts_with("rosetta_core")
    }
    let rosetta_filter =
        FilterFn::new(|metadata| metadata.module_path().is_none_or(rosetta_filter));
    let stdout_filter = LevelFilter::from_level(level).and(rosetta_filter);
    let stdout_layer = tracing_subscriber::fmt::Layer::default()
        .with_target(false) // instead include file and lines in the next lines
        .with_file(true) // display source code file paths
        .with_line_number(true) // display source code line numbers
        .with_filter(stdout_filter);

    // rolling file
    let file_appender = rolling_file::RollingFileAppender::new(
        "log/rosetta-api.log",
        rolling_file::RollingConditionBasic::new().max_size(100_000_000),
        usize::MAX,
    )
    .map_err(std::io::Error::other)?;
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    let file_layer = tracing_subscriber::fmt::Layer::default()
        .with_target(false) // instead include file and lines in the next lines
        .with_file(true) // display source code file paths
        .with_line_number(true) // display source code line numbers
        .with_writer(file_writer)
        .with_filter(LevelFilter::from_level(level));

    Registry::default()
        .with(stdout_layer)
        .with(file_layer)
        .init();

    Ok(guard)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let opt = Opt::parse();

    let _guard = init_logging(opt.log_level)?;

    if opt.log_config_file.is_some() {
        warn!("--log-config-file is deprecated and ignored")
    }

    // Check for conflicting flags
    if opt.mainnet && opt.environment != Environment::DeprecatedTestnet {
        eprintln!(
            "Cannot specify both --mainnet and --environment flags. Please use --environment production instead of --mainnet."
        );
        std::process::exit(1);
    }

    // Handle mainnet flag by treating it as environment production
    let environment = if opt.mainnet {
        warn!("--mainnet flag is deprecated. Please use --environment production instead.");
        Environment::Production
    } else {
        opt.environment
    };

    if environment == Environment::DeprecatedTestnet {
        warn!(
            "deprecated-testnet environment is deprecated. Please use --environment test instead."
        );
    }

    let pkg_name = env!("CARGO_PKG_NAME");
    let pkg_version = env!("CARGO_PKG_VERSION");
    info!("Starting {}, pkg_version: {}", pkg_name, pkg_version);
    let listen_port = match (opt.server.port, &opt.server.port_file) {
        (None, None) => 8081,
        (None, Some(_)) => 0, // random port
        (Some(p), _) => p,
    };
    info!("Listening on {}:{}", opt.server.address, listen_port);
    let addr = format!("{}:{}", opt.server.address, listen_port);

    let network_config = ParsedNetworkConfig::from_config(opt.network, &environment)
        .unwrap_or_else(|e| {
            error!("Configuration error: {}", e);
            std::process::exit(1);
        });
    info!("Internet Computer URL set to {}", network_config.ic_url);

    if network_config.root_key.is_none() {
        warn!("Data certificate will not be verified due to missing root key");
    }

    let canister_config = ParsedCanisterConfig::from_config(opt.canister, &environment)
        .unwrap_or_else(|e| {
            error!("Configuration error: {}", e);
            std::process::exit(1);
        });

    info!("Token symbol set to {}", canister_config.token_symbol);

    let store_location: Option<&Path> = match opt.storage.store_type.as_ref() {
        "sqlite" => Some(&opt.storage.location),
        "sqlite-in-memory" | "in-memory" => {
            info!("Using in-memory block store");
            None
        }
        _ => {
            error!("Invalid store type. Expected sqlite or sqlite-in-memory.");
            panic!("Invalid store type");
        }
    };

    let Opt {
        offline,
        exit_on_sync,
        not_whitelisted,
        expose_metrics,
        blockchain,
        watchdog_timeout_seconds,
        ..
    } = opt;

    // Set rosetta blocks option if feature is enabled
    #[allow(unused_mut)]
    #[allow(unused_assignments)]
    let mut enable_rosetta_blocks = false;
    #[cfg(feature = "rosetta-blocks")]
    {
        enable_rosetta_blocks = opt.enable_rosetta_blocks;
    }

    // Determine effective mainnet setting based on the environment
    let effective_mainnet =
        environment == Environment::Production || environment == Environment::Test;

    let client = ledger_client::LedgerClient::new(
        network_config.ic_url,
        canister_config.ledger_canister_id,
        canister_config.token_symbol,
        canister_config.governance_canister_id,
        store_location,
        opt.storage.max_blocks,
        offline,
        network_config.root_key,
        enable_rosetta_blocks,
        opt.storage.optimize_indexes,
    )
    .await
    .map_err(|e| {
        let msg = if effective_mainnet && !not_whitelisted && e.is_internal_error_403() {
            ", You may not be whitelisted; please try running the Rosetta server again with the '--not_whitelisted' flag"
        } else {""};
        (e, msg)
    })
    .unwrap_or_else(|(e, is_403)| panic!("Failed to initialize ledger client{is_403}: {e:?}"));

    let ledger = Arc::new(client);
    let canister_id_str = canister_config.ledger_canister_id.to_string();
    let rosetta_metrics = RosettaMetrics::new("ICP".to_string(), canister_id_str);
    let req_handler = RosettaRequestHandler::new(blockchain, ledger.clone(), rosetta_metrics);

    info!("Network id: {:?}", req_handler.network_id());
    info!(
        "Configuring watchdog with timeout of {} seconds",
        watchdog_timeout_seconds
    );
    let serv = RosettaApiServer::new(
        ledger,
        req_handler,
        addr,
        opt.server.port_file,
        expose_metrics,
        watchdog_timeout_seconds,
    )
    .expect("Error creating RosettaApiServer");

    // actix server catches kill signals. After that we still need to stop our
    // server properly
    serv.run(RosettaApiServerOpt {
        exit_on_sync,
        offline,
        mainnet: effective_mainnet,
        not_whitelisted,
    })
    .await
    .unwrap();
    serv.stop().await;
    info!("Th-th-th-that's all folks!");
    Ok(())
}
