use anyhow::{bail, Context, Result};
use axum::{
    body::Body,
    extract::Request,
    routing::{get, post},
    Router,
};
use clap::{Parser, ValueEnum};
use ic_agent::{
    agent::http_transport::reqwest_transport::ReqwestTransport, identity::AnonymousIdentity, Agent,
};
use ic_base_types::CanisterId;
use ic_icrc_rosetta::{
    common::constants::{BLOCK_SYNC_WAIT_SECS, MAX_BLOCK_SYNC_WAIT_SECS},
    common::storage::{storage_client::StorageClient, types::MetadataEntry},
    construction_api::endpoints::*,
    data_api::endpoints::*,
    ledger_blocks_synchronization::blocks_synchronizer::start_synching_blocks,
    AppState, Metadata,
};
use ic_sys::fs::write_string_using_tmp_file;
use icrc_ledger_agent::{CallMode, Icrc1Agent};
use lazy_static::lazy_static;
use std::sync::{Arc, Mutex};
use std::{path::PathBuf, process};
use tokio::{net::TcpListener, sync::Mutex as AsyncMutex};
use tower_http::classify::{ServerErrorsAsFailures, SharedClassifier};
use tower_http::trace::TraceLayer;
use tower_request_id::{RequestId, RequestIdLayer};
use tracing::level_filters::LevelFilter;
use tracing::{debug, error, error_span, info, Level, Span};
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

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    ledger_id: CanisterId,

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

    fn are_metadata_args_set(&self) -> bool {
        self.icrc1_symbol.is_some() && self.icrc1_decimals.is_some()
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
    args: &Args,
    icrc1_agent: &Icrc1Agent,
    storage: &StorageClient,
) -> anyhow::Result<Metadata> {
    if args.offline {
        let db_metadata_entries = storage.read_metadata()?;
        // If metadata is empty and the args are not set, bail out.
        if db_metadata_entries.is_empty() && !args.are_metadata_args_set() {
            bail!("Metadata must be initialized by starting Rosetta in online mode first or by providing ICRC-1 metadata arguments.");
        }

        // If metadata is set in args and not entries are found in the database,
        // return the metadata from the args.
        if args.are_metadata_args_set() && db_metadata_entries.is_empty() {
            return Ok(Metadata::from_args(
                args.icrc1_symbol.clone().unwrap(),
                args.icrc1_decimals.unwrap(),
            ));
        }

        // Populate a metadata object with the database entries.
        let db_metadata = Metadata::from_metadata_entries(&db_metadata_entries)?;
        // If the metadata args are not set, return using the db metadata.
        if !args.are_metadata_args_set() {
            return Ok(db_metadata);
        }

        // Extract the symbol and decimals from the arguments.
        let symbol = args
            .icrc1_symbol
            .clone()
            .context("ICRC-1 symbol should be provided in offline mode.")?;
        let decimals = args
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let _guard = init_logs(args.log_level, &args.log_file)?;

    let storage = Arc::new(match args.store_type {
        StoreType::InMemory => StorageClient::new_in_memory()?,
        StoreType::File => StorageClient::new_persistent(&args.store_file)?,
    });

    let network_url = args.effective_network_url();

    let ic_agent = Agent::builder()
        .with_identity(AnonymousIdentity)
        .with_transport(ReqwestTransport::create(
            Url::parse(&network_url)
                .context(format!("Failed to parse URL {}", network_url.clone()))?,
        )?)
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
        ledger_canister_id: args.ledger_id.into(),
    });

    let metadata = load_metadata(&args, &icrc1_agent, &storage).await?;
    if let Some(token_symbol) = args.icrc1_symbol.clone() {
        if metadata.symbol != token_symbol {
            bail!(
                "Provided symbol does not match symbol retrieved in online mode. Expected: {}, Got: {}",
                metadata.symbol, token_symbol
            );
        }
    }

    info!(
        "ICRC Rosetta is connected to the ICRC-1 ledger: {}",
        args.ledger_id
    );
    info!(
        "The token symbol of the ICRC-1 ledger is: {}",
        metadata.symbol
    );

    let shared_state = Arc::new(AppState {
        icrc1_agent: icrc1_agent.clone(),
        ledger_id: args.ledger_id,
        synched: Arc::new(Mutex::new(None)),
        storage: storage.clone(),
        archive_canister_ids: Arc::new(AsyncMutex::new(vec![])),
        metadata,
    });

    if args.exit_on_sync {
        if args.offline {
            bail!("'exit-on-sync' and 'offline' parameters cannot be specified at the same time.");
        }

        info!("Starting to sync blocks");
        start_synching_blocks(
            icrc1_agent.clone(),
            storage.clone(),
            *MAXIMUM_BLOCKS_PER_REQUEST,
            Arc::new(AsyncMutex::new(vec![])),
        )
        .await?;

        process::exit(0);
    }

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
        // This layer creates a span for each http request and attaches
        // the request_id, HTTP Method and path to it.
        .layer(add_request_span())
        // This layer creates a new id for each request and puts it into the
        // request extensions. Note that it should be added after the
        // Trace layer.
        .layer(RequestIdLayer)
        .with_state(shared_state.clone());

    let rosetta_url = format!("0.0.0.0:{}", args.get_port());
    let tcp_listener = TcpListener::bind(rosetta_url.clone()).await?;

    if let Some(port_file) = args.port_file {
        write_string_using_tmp_file(
            port_file,
            tcp_listener.local_addr()?.port().to_string().as_str(),
        )?;
    }

    if !args.offline {
        tokio::task::spawn_blocking(move || {
            let mut sync_wait_secs = BLOCK_SYNC_WAIT_SECS;

            let block_sync_storage = match args.store_type {
                StoreType::InMemory => storage.clone(),
                StoreType::File => {
                    Arc::new(StorageClient::new_persistent(&args.store_file).unwrap())
                }
            };

            tokio::runtime::Handle::current().block_on(async {
                loop {
                    if let Err(e) = start_synching_blocks(
                        icrc1_agent.clone(),
                        block_sync_storage.clone(),
                        *MAXIMUM_BLOCKS_PER_REQUEST,
                        shared_state.clone().archive_canister_ids.clone(),
                    )
                    .await
                    {
                        error!("Error while syncing blocks: {}", e);
                        sync_wait_secs =
                            std::cmp::min(sync_wait_secs * 2, MAX_BLOCK_SYNC_WAIT_SECS);
                        info!("Retrying in {} seconds.", sync_wait_secs);
                    } else {
                        sync_wait_secs = BLOCK_SYNC_WAIT_SECS;
                    }

                    tokio::time::sleep(std::time::Duration::from_secs(sync_wait_secs)).await;
                }
            });
        });
    }

    info!("Starting Rosetta server");
    info!("Rosetta server is listening at: {}", rosetta_url);

    axum::serve(tcp_listener, app.into_make_service())
        .await
        .context("Unable to start the Rosetta server")
}
