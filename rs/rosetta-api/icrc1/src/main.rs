#![allow(clippy::disallowed_types)]
use anyhow::{bail, Context, Result};
use axum::{
    body::Body,
    extract::Request,
    routing::{get, post},
    Router,
};
use clap::{Parser, ValueEnum};
use ic_agent::{identity::AnonymousIdentity, Agent};
use ic_base_types::{CanisterId, PrincipalId};
use ic_icrc_rosetta::common::storage::storage_client::TokenInfo;
use ic_icrc_rosetta::{
    common::constants::{BLOCK_SYNC_WAIT_SECS, MAX_BLOCK_SYNC_WAIT_SECS},
    common::storage::{storage_client::StorageClient, types::MetadataEntry},
    construction_api::endpoints::*,
    data_api::endpoints::*,
    ledger_blocks_synchronization::blocks_synchronizer::{
        start_synching_blocks, RecurrencyConfig, RecurrencyMode,
    },
    AppState, Metadata, MultiTokenAppState,
};
use ic_sys::fs::write_string_using_tmp_file;
use icrc_ledger_agent::{CallMode, Icrc1Agent};
use lazy_static::lazy_static;
use rosetta_core::metrics::RosettaMetrics;
use rosetta_core::watchdog::WatchdogThread;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::{path::PathBuf, process, time::Duration};
use tokio::{net::TcpListener, sync::Mutex as AsyncMutex};
use tower_http::classify::{ServerErrorsAsFailures, SharedClassifier};
use tower_http::trace::TraceLayer;
use tower_request_id::{RequestId, RequestIdLayer};
use tracing::{debug, error, error_span, info, warn, Level, Span};
use tracing::{level_filters::LevelFilter, Instrument};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, Registry};
use url::Url;

lazy_static! {
    static ref MAINNET_DEFAULT_URL: &'static str = "https://ic0.app";
    static ref TESTNET_DEFAULT_URL: &'static str = "https://exchanges.testnet.dfinity.network";
    static ref MAXIMUM_BLOCKS_PER_REQUEST: u64 = 2000;
}

#[derive(Clone, Debug, ValueEnum)]
enum StoreType {
    InMemory,
    File,
}

#[derive(Clone, Debug, ValueEnum)]
enum NetworkType {
    Mainnet,
    Testnet,
}

// This struct is used to parse the token definitions from the command line arguments.
// The token definitions are in the format: canister_id[:s=symbol][:d=decimals]
// The symbol and decimals are optional.
#[derive(Clone, Debug)]
struct TokenDef {
    ledger_id: CanisterId,
    // Below are optional, checked against online values if set.
    icrc1_symbol: Option<String>,
    icrc1_decimals: Option<u8>,
}

impl TokenDef {
    fn from_string(token_description: &str) -> Result<Self> {
        let parts: Vec<&str> = token_description.split(':').collect();
        if parts.is_empty() || parts.len() > 3 {
            bail!("Invalid token description: {}", token_description);
        }

        let principal_id = PrincipalId::from_str(parts[0])
            .context(format!("Failed to parse PrincipalId from {}", parts[0]))?;
        let ledger_id = CanisterId::try_from_principal_id(principal_id)?;

        let mut icrc1_symbol: Option<String> = None;
        let mut icrc1_decimals: Option<u8> = None;

        for part in parts.iter().skip(1) {
            if let Some(symbol) = part.strip_prefix("s=") {
                icrc1_symbol = Some(symbol.to_string());
            } else if let Some(decimals) = part.strip_prefix("d=") {
                icrc1_decimals = Some(
                    decimals
                        .parse()
                        .context(format!("Failed to parse u8 from {}", part))?,
                );
            } else {
                bail!(
                    "Invalid token description: {}. It must be canister_id[:s=symbol][:d=decimals]",
                    token_description
                );
            }
        }

        Ok(Self {
            ledger_id,
            icrc1_symbol,
            icrc1_decimals,
        })
    }

    fn are_metadata_args_set(&self) -> bool {
        self.icrc1_symbol.is_some() && self.icrc1_decimals.is_some()
    }
}

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    ledger_id: Option<CanisterId>,

    /// The token definitions in the format: canister_id[:s=symbol][:d=decimals]
    /// The symbol and decimals are optional.
    /// Can't be used with ledger_id.
    #[arg(long, value_delimiter = ',', num_args = 0..)]
    multi_tokens: Vec<String>,

    /// The directory where the databases for the multi-tokens will be stored.
    #[arg(long, default_value = "/data")]
    multi_tokens_store_dir: PathBuf,

    /// The symbol of the ICRC-1 token.
    /// If set Rosetta will check the symbol against the ledger it connects to. If the symbol does not match, it will exit.
    #[arg(long)]
    icrc1_symbol: Option<String>,

    #[arg(long)]
    icrc1_decimals: Option<u8>,

    /// The port to which Rosetta will bind.
    /// If not set then it will be 0.
    #[arg(short, long)]
    port: Option<u16>,

    /// The file where the port to which Rosetta will bind
    /// will be written.
    #[arg(short = 'P', long)]
    port_file: Option<PathBuf>,

    /// The type of the store to use.
    #[arg(short, long, value_enum, default_value_t = StoreType::File)]
    store_type: StoreType,

    /// The file to use for the store if [store_type] is file.
    #[arg(short = 'f', long, default_value = "/data/db.sqlite")]
    store_file: PathBuf,

    /// The network type that rosetta connects to.
    #[arg(short = 'n', long, value_enum)]
    network_type: NetworkType,

    /// URL of the IC to connect to.
    /// Default Mainnet URL is: https://ic0.app,
    /// Default Testnet URL is: https://exchanges.testnet.dfinity.network
    #[arg(long, short = 'u')]
    network_url: Option<String>,

    #[arg(short = 'L', long, default_value_t = Level::INFO)]
    log_level: Level,

    /// Set this option to only do one full sync of the ledger and then exit rosetta
    #[arg(long = "exit-on-sync")]
    exit_on_sync: bool,

    /// Set this option to only run the rosetta server, no block synchronization will be performed and no transactions can be submitted in this mode.
    #[arg(long)]
    offline: bool,

    /// The file to use for storing logs.
    #[arg(long = "log-file", default_value = "log/rosetta-api.log")]
    log_file: PathBuf,

    /// Timeout in seconds for sync watchdog. If no synchronization is attempted within this time, the sync thread will be restarted.
    #[arg(long = "watchdog-timeout-seconds", default_value = "60")]
    watchdog_timeout_seconds: u64,
}

impl Args {
    /// Return the port to which Rosetta should bind to.
    fn get_port(&self) -> u16 {
        match (&self.port, &self.port_file) {
            (None, None) => 8080,
            (None, Some(_)) => 0,
            (Some(port), _) => *port,
        }
    }
    fn is_mainnet(&self) -> bool {
        match self.network_type {
            NetworkType::Mainnet => true,
            NetworkType::Testnet => false,
        }
    }

    fn effective_network_url(&self) -> String {
        self.network_url.clone().unwrap_or_else(|| {
            if self.is_mainnet() {
                (*MAINNET_DEFAULT_URL).to_string()
            } else {
                (*TESTNET_DEFAULT_URL).to_string()
            }
        })
    }
}

fn init_logs(log_level: Level, log_file_path: &PathBuf) -> anyhow::Result<WorkerGuard> {
    let stdout_layer = tracing_subscriber::fmt::Layer::default()
        .with_target(false) // instead include file and lines in the next lines
        .with_file(true) // display source code file paths
        .with_line_number(true) // display source code line numbers
        .with_filter(LevelFilter::from_level(log_level));

    // rolling file
    std::fs::create_dir_all(log_file_path.parent().ok_or(anyhow::Error::msg(format!(
        "Could not find the parent directory of {}",
        log_file_path.display()
    )))?)?;
    let file_appender = rolling_file::RollingFileAppender::new(
        log_file_path,
        rolling_file::RollingConditionBasic::new().max_size(100_000_000),
        usize::MAX,
    )?;
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    let file_layer = tracing_subscriber::fmt::Layer::default()
        .with_target(false) // instead include file and lines in the next lines
        .with_file(true) // display source code file paths
        .with_line_number(true) // display source code line numbers
        .with_writer(file_writer)
        .with_filter(LevelFilter::from_level(log_level));

    Registry::default()
        .with(stdout_layer)
        .with(file_layer)
        .init();

    Ok(guard)
}

type FnTraceLayer =
    TraceLayer<SharedClassifier<ServerErrorsAsFailures>, fn(&Request<Body>) -> Span>;

fn add_request_span() -> FnTraceLayer {
    // See tower-request-id crate and the example at
    // https://github.com/imbolc/tower-request-id/blob/fe372479a56bd540784b87812d4d78473e43c6d4/examples/logging.rs

    // Let's create a tracing span for each request
    TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
        // We get the request id from the extensions
        let request_id = request
            .extensions()
            .get::<RequestId>()
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown".into());
        // And then we put it along with other information into the `request` span
        error_span!(
            "request",
            id = %request_id,
            method = %request.method(),
            uri = %request.uri(),
        )
    })
}

async fn load_metadata(
    token_def: &TokenDef,
    icrc1_agent: &Icrc1Agent,
    storage: &StorageClient,
    is_offline: bool,
) -> anyhow::Result<Metadata> {
    if is_offline {
        let db_metadata_entries = storage.read_metadata()?;
        let are_metadata_set = token_def.are_metadata_args_set();
        // If metadata is empty and the args are not set, bail out.
        if db_metadata_entries.is_empty() && !are_metadata_set {
            bail!("Metadata must be initialized by starting Rosetta in online mode first or by providing ICRC-1 metadata arguments.");
        }

        // If metadata is set in args and not entries are found in the database,
        // return the metadata from the args.
        if are_metadata_set && db_metadata_entries.is_empty() {
            return Ok(Metadata::from_args(
                token_def.icrc1_symbol.clone().unwrap(),
                token_def.icrc1_decimals.unwrap(),
            ));
        }

        // Populate a metadata object with the database entries.
        let db_metadata = Metadata::from_metadata_entries(&db_metadata_entries)?;
        // If the metadata args are not set, return using the db metadata.
        if !are_metadata_set {
            return Ok(db_metadata);
        }

        // Extract the symbol and decimals from the arguments.
        let symbol = token_def
            .icrc1_symbol
            .clone()
            .context("ICRC-1 symbol should be provided in offline mode.")?;
        let decimals = token_def
            .icrc1_decimals
            .context("ICRC-1 decimals should be provided in offline mode.")?;

        // If the database entries is empty, return the metadata as no validation
        // can be done.
        if db_metadata_entries.is_empty() {
            return Ok(Metadata::from_args(symbol, decimals));
        }

        // Populate a metadata object with the database entries.
        let db_metadata = Metadata::from_metadata_entries(&db_metadata_entries)?;

        // If the symbols do not match, bail out.
        if db_metadata.symbol != symbol {
            bail!(
                "Provided symbol does not match symbol retrieved in online mode. Expected: {}",
                db_metadata.symbol
            );
        }

        // If the decimals do not match, bail out.
        if db_metadata.decimals != decimals {
            bail!(
                "Provided decimals does not match symbol retrieved in online mode. Expected: {}",
                db_metadata.decimals
            );
        }

        return Ok(db_metadata);
    }

    let ic_metadata_entries = icrc1_agent
        .metadata(CallMode::Update)
        .await
        .with_context(|| "Failed to get metadata")?
        .iter()
        .map(|(key, value)| MetadataEntry::from_metadata_value(key, value))
        .collect::<Result<Vec<MetadataEntry>>>()?;

    storage.write_metadata(ic_metadata_entries.clone())?;

    Metadata::from_metadata_entries(&ic_metadata_entries)
}

// Parses TokenDefs from the command line arguments.
fn extract_token_defs(args: &Args) -> Result<Vec<TokenDef>> {
    let mut input_tokens = args.multi_tokens.clone();

    // If no tokens are provided, use the legacy arguments
    if input_tokens.is_empty() {
        if args.ledger_id.is_none() {
            bail!("No token definitions provided");
        }

        let mut token_dec = format!("{}", args.ledger_id.unwrap(),);

        if args.icrc1_symbol.is_some() {
            token_dec.push_str(&format!(":s={}", args.icrc1_symbol.clone().unwrap()));
        }

        if args.icrc1_decimals.is_some() {
            token_dec.push_str(&format!(":d={}", args.icrc1_decimals.unwrap()));
        }

        input_tokens.push(token_dec);
    } else {
        if args.ledger_id.is_some() {
            bail!("Cannot provide both multi-tokens and ledger-id");
        }
        if args.icrc1_symbol.is_some() {
            bail!("Cannot provide both multi-tokens and icrc1-symbol");
        }
        if args.icrc1_decimals.is_some() {
            bail!("Cannot provide both multi-tokens and icrc1-decimals");
        }
    }

    let token_defs: Vec<TokenDef> = input_tokens
        .iter()
        .map(|token_description| TokenDef::from_string(token_description))
        .collect::<Result<Vec<TokenDef>>>()?;

    Ok(token_defs)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let _guard = init_logs(args.log_level, &args.log_file)?;

    // Initialize rosetta metrics with a default canister ID
    // This will be updated for specific token operations but is required for middleware setup
    let rosetta_metrics = RosettaMetrics::new("icrc1".to_string(), "icrc1_default".to_string());

    let token_defs = extract_token_defs(&args)?;
    let mut token_states = HashMap::new();

    let num_tokens = token_defs.len();
    let mut num_failed_tokens = 0;

    for token_def in token_defs.iter() {
        let network_url = args.effective_network_url();

        let ic_agent = Agent::builder()
            .with_identity(AnonymousIdentity)
            .with_url(
                Url::parse(&network_url)
                    .context(format!("Failed to parse URL {}", network_url.clone()))?,
            )
            .with_http_client(reqwest::Client::new())
            .build()?;

        // Only fetch root key if the network is not the mainnet
        if !args.is_mainnet() {
            debug!("Network type is not mainnet --> Trying to fetch root key");
            ic_agent.fetch_root_key().await?;
        }

        debug!("Rosetta connects to : {}", network_url);

        debug!(
            "Network status is : {:?}",
            ic_agent.status().await?.replica_health_status
        );

        let icrc1_agent = Arc::new(Icrc1Agent {
            agent: ic_agent,
            ledger_canister_id: token_def.ledger_id.into(),
        });

        let mut storage = match args.store_type {
            StoreType::InMemory => StorageClient::new_in_memory()?,
            StoreType::File => {
                let mut path = args.multi_tokens_store_dir.clone();
                path.push(format!("{}.db", PrincipalId::from(token_def.ledger_id)));
                StorageClient::new_persistent(&path).unwrap_or_else(|err| {
                    panic!("error creating persistent storage '{:?}': {}", path, err)
                })
            }
        };

        let metadata = match load_metadata(token_def, &icrc1_agent, &storage, args.offline).await {
            Ok(metadata) => metadata,
            Err(err) => {
                warn!(
                    "Failed to load metadata for token {}: {:?}",
                    token_def.ledger_id, err
                );
                num_failed_tokens += 1;
                continue;
            }
        };

        if token_def.icrc1_symbol.is_some()
            && metadata.symbol != token_def.icrc1_symbol.clone().unwrap()
        {
            bail!(
                    "Provided symbol does not match symbol retrieved in online mode. Expected: {}, Got: {}",
                    metadata.symbol, token_def.icrc1_symbol.clone().unwrap()
                );
        }

        info!(
            "ICRC Rosetta is connected to the ICRC-1 ledger: {}",
            token_def.ledger_id
        );
        info!(
            "The token symbol of the ICRC-1 ledger is: {}",
            metadata.symbol
        );

        let storage_metadata = metadata.clone();

        storage.initialize(TokenInfo::new(
            storage_metadata.symbol,
            storage_metadata.decimals,
            token_def.ledger_id,
        ));

        let shared_state = Arc::new(AppState {
            icrc1_agent: icrc1_agent.clone(),
            ledger_id: token_def.ledger_id,
            synched: Arc::new(Mutex::new(None)),
            storage: Arc::new(storage),
            archive_canister_ids: Arc::new(AsyncMutex::new(vec![])),
            metadata,
        });

        token_states.insert(token_def.ledger_id.to_string(), shared_state.clone());
    }

    let token_app_states = Arc::new(MultiTokenAppState {
        token_states: token_states.clone(),
    });

    if args.exit_on_sync {
        if args.offline {
            bail!("'exit-on-sync' and 'offline' parameters cannot be specified at the same time.");
        }

        info!("Starting to sync blocks");
        let futures = token_app_states
            .token_states
            .values()
            .map(|shared_state| async move {
                start_synching_blocks(
                    shared_state.icrc1_agent.clone(),
                    shared_state.storage.clone(),
                    *MAXIMUM_BLOCKS_PER_REQUEST,
                    shared_state.archive_canister_ids.clone(),
                    RecurrencyMode::OneShot,
                    Box::new(|| {}), // <-- no-op heartbeat
                )
                .await
            });
        let results = futures::future::join_all(futures).await;

        for result in results {
            if let Err(err) = result {
                bail!("Failed to sync blocks: {}", err);
            }
        }
        process::exit(0);
    }

    if num_failed_tokens == num_tokens {
        warn!("Failed to load metadata for any token. Rosetta will exit.");
        bail!("No metadata loaded for any token.");
    } else if num_failed_tokens > 0 {
        warn!(
            "Failed to load metadata for {} out of {} tokens. Rosetta will continue with the rest.",
            num_failed_tokens, num_tokens
        );
    } else {
        info!(
            "Successfully loaded metadata for all {} tokens.",
            num_tokens
        );
    }

    // Create metrics middleware for Axum
    let metrics_layer = rosetta_metrics.metrics_layer();

    let app = Router::new()
        .route("/ready", get(ready))
        .route("/health", get(health))
        .route("/call", post(call))
        .route("/network/list", post(network_list))
        .route("/network/options", post(network_options))
        .route("/network/status", post(network_status))
        .route("/block", post(block))
        .route("/account/balance", post(account_balance))
        .route("/block/transaction", post(block_transaction))
        .route("/search/transactions", post(search_transactions))
        .route("/mempool", post(mempool))
        .route("/mempool/transaction", post(mempool_transaction))
        .route("/construction/derive", post(construction_derive))
        .route("/construction/preprocess", post(construction_preprocess))
        .route("/construction/metadata", post(construction_metadata))
        .route("/construction/combine", post(construction_combine))
        .route("/construction/submit", post(construction_submit))
        .route("/construction/hash", post(construction_hash))
        .route("/construction/payloads", post(construction_payloads))
        .route("/construction/parse", post(construction_parse))
        // Apply the metrics middleware
        .layer(metrics_layer)
        // This layer creates a span for each http request and attaches
        // the request_id, HTTP Method and path to it.
        .layer(add_request_span())
        // This layer creates a new id for each request and puts it into the
        // request extensions. Note that it should be added after the
        // Trace layer.
        .layer(RequestIdLayer)
        .with_state(token_app_states.clone());

    let rosetta_url = format!("0.0.0.0:{}", args.get_port());
    let tcp_listener = TcpListener::bind(rosetta_url.clone()).await?;

    if let Some(port_file) = args.port_file {
        write_string_using_tmp_file(
            port_file,
            tcp_listener.local_addr()?.port().to_string().as_str(),
        )?;
    }

    if !args.offline {
        // For each token state, spawn a watchdog thread that repeatedly syncs blocks.
        for shared_state in token_app_states.token_states.values() {
            let token_name = shared_state.ledger_display_name();
            let shared_state = Arc::clone(shared_state);
            let span = tracing::info_span!("sync", token = %token_name);
            let span_watchdog = span.clone();

            info!(
                "Configuring watchdog for {} with timeout of {} seconds",
                token_name, args.watchdog_timeout_seconds
            );

            tokio::spawn(
                async move {
                    // First heartbeat might take hours until the ledger is initially synced,
                    // so we skip it to avoid the watchdog thread to restart the sync thread
                    // during the initial synchronization.
                    let skip_first_hearbeat = true;
                    let local_state = Arc::clone(&shared_state);
                    let mut watchdog = WatchdogThread::new(
                        Duration::from_secs(args.watchdog_timeout_seconds),
                        Some(Arc::new(move || {
                            local_state.storage.get_metrics().inc_sync_thread_restarts();
                            info!("Watchdog triggered restart for a sync thread");
                        })),
                        skip_first_hearbeat,
                        Some(span_watchdog.clone()),
                    );
                    let span_watchdog = span_watchdog.clone();
                    watchdog.start(move |heartbeat| {
                        let shared_state = Arc::clone(&shared_state);
                        let span_watchdog = span_watchdog.clone();
                        tokio::spawn(
                            async move {
                                if let Err(e) = start_synching_blocks(
                                    shared_state.icrc1_agent.clone(),
                                    shared_state.storage.clone(),
                                    *MAXIMUM_BLOCKS_PER_REQUEST,
                                    shared_state.archive_canister_ids.clone(),
                                    RecurrencyMode::Recurrent(RecurrencyConfig {
                                        min_recurrency_wait: Duration::from_secs(
                                            BLOCK_SYNC_WAIT_SECS,
                                        ),
                                        max_recurrency_wait: Duration::from_secs(
                                            MAX_BLOCK_SYNC_WAIT_SECS,
                                        ),
                                        backoff_factor: 2,
                                    }),
                                    Box::new(heartbeat),
                                )
                                .await
                                {
                                    error!(
                                        "Sync error for token {:?}: {:?}",
                                        shared_state.ledger_id, e
                                    );
                                }
                            }
                            .instrument(span_watchdog),
                        )
                    });
                }
                .instrument(span),
            );
        }
    }

    info!("Starting Rosetta server");
    info!("Rosetta server is listening at: {}", rosetta_url);

    axum::serve(tcp_listener, app.into_make_service())
        .await
        .context("Unable to start the Rosetta server")
}
