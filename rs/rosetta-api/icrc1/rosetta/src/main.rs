use anyhow::{Context, Result};
use axum::{http::StatusCode, routing::get, Json, Router};
use clap::{Parser, ValueEnum};
use ic_icrc_rosetta::common::storage::storage_client::StorageClient;
use std::net::TcpListener;
use std::path::PathBuf;

#[derive(Clone, Debug, ValueEnum)]
enum StoreType {
    InMemory,
    File,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
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

async fn health() -> (StatusCode, Json<()>) {
    (StatusCode::OK, Json(()))
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let _storage = match args.store_type {
        StoreType::InMemory => StorageClient::new_in_memory()?,
        StoreType::File => StorageClient::new_persistent(&args.store_file)?,
    };

    let app = Router::new().route("/health", get(health));

    let tcp_listener = TcpListener::bind(format!("0.0.0.0:{}", args.get_port()))?;

    if let Some(port_file) = args.port_file {
        std::fs::write(port_file, tcp_listener.local_addr()?.to_string())?;
    }

    axum::Server::from_tcp(tcp_listener)?
        .serve(app.into_make_service())
        .await
        .context("Unable to start the Rosetta server")
}
