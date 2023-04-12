use anyhow::{Context, Result};
use axum::{
    routing::{get, post},
    Router,
};
use clap::{Parser, ValueEnum};
use endpoints::{health, network_list, network_options};
use ic_base_types::CanisterId;
use ic_icrc_rosetta::{common::storage::storage_client::StorageClient, AppState};
use std::path::PathBuf;
use std::{net::TcpListener, sync::Arc};

mod endpoints;

#[derive(Clone, Debug, ValueEnum)]
enum StoreType {
    InMemory,
    File,
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
