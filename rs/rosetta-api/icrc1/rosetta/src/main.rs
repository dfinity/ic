use anyhow::{Context, Result};
use axum::{
    routing::{get, post},
    Router,
};
use clap::{Parser, ValueEnum};
use endpoints::{health, network_list, network_options};
use ic_agent::{
    agent::http_transport::ReqwestHttpReplicaV2Transport, identity::AnonymousIdentity, Agent,
};
use ic_base_types::CanisterId;
use ic_icrc_rosetta::{common::storage::storage_client::StorageClient, AppState};
use icrc_ledger_agent::Icrc1Agent;
use lazy_static::lazy_static;
use log::debug;
use std::path::PathBuf;
use std::{net::TcpListener, sync::Arc};
use url::Url;
mod endpoints;

lazy_static! {
    static ref MAINNET_DEFAULT_URL: &'static str = "https://ic0.app";
    static ref TESTNET_DEFAULT_URL: &'static str = "https://exchanges.testnet.dfinity.network";
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

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let storage = match args.store_type {
        StoreType::InMemory => StorageClient::new_in_memory()?,
        StoreType::File => StorageClient::new_persistent(&args.store_file)?,
    };

    let shared_state = Arc::new(AppState {
        ledger_id: args.ledger_id,
        _storage: storage,
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

    let _icrc1_agent = Icrc1Agent {
        agent: ic_agent,
        ledger_canister_id: args.ledger_id.into(),
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/network/list", post(network_list))
        .route("/network/options", post(network_options))
        .with_state(shared_state);

    let tcp_listener = TcpListener::bind(format!("0.0.0.0:{}", args.get_port()))?;

    if let Some(port_file) = args.port_file {
        std::fs::write(port_file, tcp_listener.local_addr()?.to_string())?;
    }

    axum::Server::from_tcp(tcp_listener)?
        .serve(app.into_make_service())
        .await
        .context("Unable to start the Rosetta server")
}
