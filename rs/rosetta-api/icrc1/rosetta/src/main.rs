use anyhow::{Context, Result};
use axum::{
    body::Body,
    routing::{get, post},
    Router,
};
use clap::{Parser, ValueEnum};
use endpoints::{health, network_list, network_options, network_status};
use http::Request;
use ic_agent::{
    agent::http_transport::ReqwestHttpReplicaV2Transport, identity::AnonymousIdentity, Agent,
};
use ic_base_types::CanisterId;
use ic_icrc_rosetta::{
    common::storage::storage_client::StorageClient,
    ledger_blocks_synchronization::blocks_synchronizer::start_synching_blocks, AppState,
};
use icrc_ledger_agent::Icrc1Agent;
use lazy_static::lazy_static;
use std::{net::TcpListener, sync::Arc};
use std::{path::PathBuf, process};
use tower_http::classify::{ServerErrorsAsFailures, SharedClassifier};
use tower_http::trace::TraceLayer;
use tower_request_id::{RequestId, RequestIdLayer};
use tracing::{debug, error_span, info, Level, Span};
use url::Url;

mod endpoints;

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
    #[arg(short = 'f', long, default_value = "db.sqlite")]
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

fn init_logs(log_level: Level) {
    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false) // instead include file and lines in the next lines
        .with_file(true) // display source code file paths
        .with_line_number(true) // display source code line numbers
        .init();
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    init_logs(args.log_level);

    let storage = Arc::new(match args.store_type {
        StoreType::InMemory => StorageClient::new_in_memory()?,
        StoreType::File => StorageClient::new_persistent(&args.store_file)?,
    });

    let shared_state = Arc::new(AppState {
        ledger_id: args.ledger_id,
        storage: storage.clone(),
    });

    let network_url = args.effective_network_url();

    let ic_agent = Agent::builder()
        .with_identity(AnonymousIdentity)
        .with_transport(ReqwestHttpReplicaV2Transport::create(
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

    if !args.offline {
        info!("Starting to sync blocks");
        start_synching_blocks(
            icrc1_agent.clone(),
            storage.clone(),
            *MAXIMUM_BLOCKS_PER_REQUEST,
        )
        .await?;
    }

    // If the option of exiting after the synchronization is completed is set we can exit rosetta
    if args.exit_on_sync {
        process::exit(0);
    }

    let app = Router::new()
        .route("/health", get(health))
        .route("/network/list", post(network_list))
        .route("/network/options", post(network_options))
        .route("/network/status", post(network_status))
        // This layer creates a span for each http request and attaches
        // the request_id, HTTP Method and path to it.
        .layer(add_request_span())
        // This layer creates a new id for each request and puts it into the
        // request extensions. Note that it should be added after the
        // Trace layer.
        .layer(RequestIdLayer)
        .with_state(shared_state);

    let tcp_listener = TcpListener::bind(format!("0.0.0.0:{}", args.get_port()))?;

    if let Some(port_file) = args.port_file {
        std::fs::write(port_file, tcp_listener.local_addr()?.port().to_string())?;
    }

    info!("Starting Rosetta server");

    axum::Server::from_tcp(tcp_listener)?
        .serve(app.into_make_service())
        .await
        .context("Unable to start the Rosetta server")
}
