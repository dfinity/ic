// TODO: Remove after inspect_err stabilizes (rust-lang/rust#91345)

#![allow(unstable_name_collisions)]

use std::{net::SocketAddr, path::PathBuf};

use anyhow::Context;
use clap::{builder::ValueParser, Parser};
use futures::try_join;
use hyperlocal::Uri as UnixUri;
use jemallocator::Jemalloc;
use tracing::{error, Instrument};

mod canister_alias;
mod canister_id;
mod config;
mod domain_addr;
mod error;
mod http;
mod http_client;
mod logging;
mod metrics;
mod proxy;
mod validate;

use crate::{
    canister_alias::{parse_canister_alias, CanisterAlias},
    domain_addr::{parse_domain_addr, DomainAddr},
    metrics::{MetricParams, WithMetrics},
    proxy::ListenProto,
    validate::Validator,
};

#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

// TODO: Remove after inspect_err stabilizes (rust-lang/rust#91345)
trait InspectErr {
    type E;
    fn inspect_err<F: FnOnce(&Self::E)>(self, f: F) -> Self;
}

impl<R, E> InspectErr for Result<R, E> {
    type E = E;
    fn inspect_err<F: FnOnce(&Self::E)>(self, f: F) -> Self {
        if let Err(ref e) = self {
            f(e);
        }

        self
    }
}

#[derive(Parser)]
struct Opts {
    /// The address to bind to.
    #[clap(long)]
    address: Option<SocketAddr>,

    /// Unix socket to listen on. If address is specified too - it takes precedence
    #[clap(long)]
    unix_socket: Option<PathBuf>,

    /// A list of replica mappings from domains to socket addresses for replica upstreams.
    /// Format: <URL>[|<IP>:<PORT>]
    #[clap(long, value_parser = ValueParser::new(parse_domain_addr), default_value = "http://localhost:8000/")]
    replica: Vec<DomainAddr>,

    /// Replica's Unix Socket. Overrides `--replica`
    #[clap(long)]
    replica_unix_socket: Option<PathBuf>,

    /// A list of domains that can be served. These are used for canister resolution.
    #[clap(long, default_value = "localhost")]
    domain: Vec<String>,

    /// A list of mappings from canister names to canister principals.
    /// Format: name:principal
    #[clap(long, value_parser = ValueParser::new(parse_canister_alias))]
    canister_alias: Vec<CanisterAlias>,

    /// The list of custom root HTTPS certificates to use to talk to the replica. This can be used
    /// to connect to an IC that has a self-signed certificate, or to limit the certificates. Do not use this
    /// when talking to the Internet Computer blockchain mainnet unless you know what you're doing.
    #[clap(long)]
    ssl_root_certificate: Vec<PathBuf>,

    /// The root key to use to communicate with the replica back end. By default, the Internet Computer
    /// mainnet key is used (embedded in the binary). Ensure you know what you are doing before
    /// using this option.
    #[clap(long, conflicts_with("fetch_root_key"))]
    root_key: Option<PathBuf>,

    /// Whether or not to fetch the root key from the replica back end. Do not use this when
    /// talking to the Internet Computer blockchain mainnet as it is unsecure.
    #[clap(long)]
    fetch_root_key: bool,

    /// Allows HTTPS connection to replicas with invalid HTTPS certificates. This can be used to
    /// connect to an IC that has a self-signed certificate, for example. Do not use this when
    /// talking to the Internet Computer blockchain mainnet as it is *VERY* unsecure.
    #[clap(long)]
    danger_accept_invalid_ssl: bool,

    /// Whether or not this is run in a debug context (e.g. errors returned in responses
    /// should show full stack and error details).
    #[clap(long)]
    debug: bool,

    /// The options for logging
    #[clap(flatten)]
    log: logging::LoggingOpts,

    /// The options for metrics
    #[clap(flatten)]
    metrics: metrics::MetricsOpts,
}

fn main() -> Result<(), anyhow::Error> {
    let Opts {
        address,
        unix_socket,
        replica,
        replica_unix_socket,
        domain,
        canister_alias,
        ssl_root_certificate,
        fetch_root_key,
        danger_accept_invalid_ssl,
        debug,
        log,
        metrics,
        root_key,
    } = Opts::parse();

    let _span = logging::setup(log);

    // Setup Metrics
    let (meter, metrics) = metrics::setup(metrics);

    // Setup Canister ID Resolver
    let resolver = canister_id::setup(canister_id::CanisterIdOpts {
        canister_alias,
        domain,
    })?;

    // Setup Validator
    let validator = Validator::new();
    let validator = WithMetrics(validator, MetricParams::new(&meter, "validator"));

    let listen = address
        .map(ListenProto::Tcp)
        .or(unix_socket.map(ListenProto::Unix))
        .expect("must specify either address or unix_socket");

    let proxy = if let Some(v) = replica_unix_socket {
        let uri = UnixUri::new(v, "/");
        let client = http_client::setup_unix_socket(uri.into())?;

        proxy::setup_unix_socket(
            proxy::SetupArgs {
                resolver,
                validator,
                client,
                meter: meter.clone(),
            },
            proxy::ProxyOpts {
                listen,
                replicas: vec![],
                debug,
                fetch_root_key,
                root_key,
            },
        )?
    } else {
        let client = http_client::setup(http_client::HttpClientOpts {
            ssl_root_certificate,
            danger_accept_invalid_ssl,
            replicas: &replica,
        })?;

        proxy::setup(
            proxy::SetupArgs {
                resolver,
                validator,
                client,
                meter: meter.clone(),
            },
            proxy::ProxyOpts {
                listen,
                replicas: replica,
                debug,
                fetch_root_key,
                root_key,
            },
        )?
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(
        async move {
            try_join!(
                metrics.run().in_current_span(),
                proxy.run().in_current_span(),
            )
            .context("Runtime crashed")
            .inspect_err(|e| error!("{e}"))?;
            Ok::<_, anyhow::Error>(())
        }
        .in_current_span(),
    )?;

    Ok(())
}
