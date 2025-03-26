use std::{collections::HashSet, net::SocketAddr, sync::Arc};

use anyhow::Error;
use axum::{routing::get, Router};
use clap::Parser;
use client::ReqwestClient;
use reqwest::Client;
use url::Url;

mod api;
mod client;

#[derive(Parser)]
pub struct Cli {
    /// Address for serving requests
    #[clap(long, default_value = "127.0.0.1:19532")]
    pub addr: SocketAddr,

    /// systemd-journal-gatewayd URL
    #[clap(long, default_value = "http://localhost:19531/")]
    pub upstream: Url,

    /// List of systemd units to allow log access for
    #[clap(long, value_delimiter = ',', default_value = "")]
    pub units: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();

    // http client
    let c = ReqwestClient(Client::new());
    let c = Arc::new(c);

    // api
    let app = Router::new().route(
        "/entries",
        get(api::entries).with_state((
            cli.upstream.join("/entries")?,            // upstream_url
            HashSet::from_iter(cli.units.into_iter()), // units
            c.clone(),                                 // http_client
        )),
    );

    let listener = tokio::net::TcpListener::bind(&cli.addr).await.unwrap();
    axum::serve(listener, app.into_make_service()).await?;

    Ok(())
}
