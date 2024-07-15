use std::{collections::HashSet, fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Error};
use candid::Principal;
use clap::{builder::ValueParser, Parser};
use futures::try_join;
use hyperlocal_next::Uri as UnixUri;
use tracing::{error, warn, Instrument};

use crate::{
    canister_alias::{parse_canister_alias, CanisterAlias},
    canister_id,
    domain_addr::{parse_domain_addr, DomainAddr},
    http_client, logging,
    metrics::{self, MetricParams, WithMetrics},
    proxy::{self, ListenProto},
    validate::Validator,
};

// Generic function to load a list of canister ids from a text file into a HashSet
pub fn load_canister_list(path: PathBuf) -> Result<HashSet<Principal>, Error> {
    let data = fs::read_to_string(path).context("failed to read canisters file")?;
    let set = data
        .lines()
        .filter(|x| !x.trim().is_empty())
        .map(Principal::from_text)
        .collect::<Result<HashSet<Principal>, _>>()?;
    Ok(set)
}

#[derive(Parser)]
pub struct Opts {
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

    /// Regex to match domain allowed to serve system subnets canisters
    #[clap(long)]
    domain_system_regex: Vec<String>,

    /// Domain allowed to serve normal canisters
    #[clap(long)]
    domain_app_regex: Vec<String>,

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

    /// Path to a list of pre-isolation canister ids, one per line
    #[clap(long)]
    pre_isolation_canisters: Option<PathBuf>,

    /// Path to a MaxMind GeoIP2 database
    #[clap(long)]
    geoip_db: Option<PathBuf>,

    /// Denylist URL
    #[clap(long)]
    denylist_url: Option<String>,

    /// Path to an initial denylist snapshot
    #[clap(long)]
    denylist_initial: Option<PathBuf>,

    /// Interval to update denylist in seconds
    #[clap(long, default_value = "60")]
    denylist_interval: u64,

    /// Allowlist that takes precedence over denylist
    #[clap(long)]
    allowlist: Option<PathBuf>,

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

pub fn main(opts: Opts) -> Result<(), Error> {
    let Opts {
        address,
        unix_socket,
        replica,
        replica_unix_socket,
        domain,
        domain_system_regex,
        domain_app_regex,
        canister_alias,
        pre_isolation_canisters,
        geoip_db,
        denylist_url,
        denylist_initial,
        denylist_interval,
        allowlist,
        ssl_root_certificate,
        fetch_root_key,
        danger_accept_invalid_ssl,
        debug,
        log,
        metrics,
        root_key,
    } = opts;

    let _span = logging::setup(log);

    // Setup Metrics
    let (meter, metrics) = metrics::setup(metrics);

    // Setup domain-canister matching
    let domain_match = pre_isolation_canisters.map(|x| {
        if domain_app_regex.is_empty() || domain_system_regex.is_empty() {
            panic!("if --pre-isolation-canisters list is specified then --domain-app-regex and --domain-system-regex should also be");
        }

        let pre_isolation_canisters = load_canister_list(x).expect("uname to load pre-isolation canisters");
        warn!("{} pre-isolation canisters loaded", pre_isolation_canisters.len());

        Ok::<_, Error>(Arc::new(proxy::domain_canister::DomainCanisterMatcher::new(
            pre_isolation_canisters,
            domain_app_regex,
            domain_system_regex,
        )?))
    }).transpose()?;

    // Setup GeoIP
    let geoip = geoip_db
        .map(proxy::geoip::GeoIp::new)
        .transpose()?
        .map(Arc::new);

    // Setup denylisting
    let denylist = if denylist_url.is_some() || denylist_initial.is_some() {
        let allowlist = allowlist
            .map(load_canister_list)
            .transpose()?
            .unwrap_or_default();

        let dl = proxy::denylist::Denylist::new(denylist_url, allowlist);

        // Load initial list if provided
        if let Some(v) = denylist_initial {
            let data = fs::read(v).context("unable to read initial denylist")?;
            let count = dl.load_json(&data)?;
            warn!("Initial denylist loaded with {count} canisters");
        }

        Some(Arc::new(dl))
    } else {
        None
    };

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
                domain_match,
                geoip,
                denylist: denylist.clone(),
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
                domain_match,
                geoip,
                denylist: denylist.clone(),
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
                async {
                    if let Some(v) = denylist {
                        v.run(Duration::from_secs(denylist_interval), &meter).await
                    } else {
                        Ok(())
                    }
                }
            )
            .context("Runtime crashed")
            .inspect_err(|e| error!("{e}"))?;
            Ok::<_, Error>(())
        }
        .in_current_span(),
    )?;

    Ok(())
}
