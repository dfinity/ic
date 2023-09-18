use anyhow::{bail, Result};
use clap::Parser;
use futures_util::FutureExt;
use humantime::parse_duration;
use ic_agent::export::Principal;
use ic_async_utils::shutdown_signal;
use ic_metrics::MetricsRegistry;
use obs_canister_clients::node_status_canister_client::NodeStatusCanister;
use prometheus_http_query::Client;
use service_discovery::{
    job_types::JobType, metrics::Metrics, poll_loop::make_poll_loop,
    registry_sync::sync_local_registry, IcServiceDiscoveryImpl,
};
use slog::{info, o, Drain};
use std::{path::PathBuf, sync::Arc, time::Duration};
use url::Url;

mod canister_updater_loop;

fn main() -> Result<()> {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).chan_size(8192).build();
    let log = slog::Logger::root(drain.fuse(), o!());

    let cli_args = CliArgs::parse().validate()?;
    let rt = tokio::runtime::Runtime::new()?;
    let shutdown_signal = shutdown_signal(log.clone()).shared();
    let mut handles = vec![];

    let metrics_registry = MetricsRegistry::new();
    let metrics = Metrics::new(metrics_registry.clone());

    info!(log, "Starting service discovery ...");
    let mercury_dir = cli_args.targets_dir.join("mercury");
    let nns_url = vec![cli_args.nns_url.clone()];
    rt.block_on(sync_local_registry(
        log.clone(),
        mercury_dir,
        nns_url,
        cli_args.skip_sync,
        None,
    ));

    info!(log, "Starting IcServiceDiscovery ...");
    let ic_discovery = Arc::new(IcServiceDiscoveryImpl::new(
        log.clone(),
        cli_args.targets_dir,
        cli_args.registry_query_timeout,
        [(JobType::Replica, 9090)]
            .iter()
            .map(|(j, p)| (*j, *p))
            .collect(),
    )?);

    let (stop_signal_sender, stop_signal_rcv) = crossbeam::channel::bounded::<()>(0);
    let (update_signal_sender, update_signal_rcv) = crossbeam::channel::bounded::<()>(0);
    let poll_loop = make_poll_loop(
        log.clone(),
        rt.handle().clone(),
        ic_discovery.clone(),
        stop_signal_rcv.clone(),
        cli_args.poll_interval,
        metrics.clone(),
        Some(update_signal_sender),
        1,
    );

    info!(
        log,
        "Spawning scraping thread. Interval: {:?}", cli_args.poll_interval
    );
    let join_handle = std::thread::spawn(poll_loop);
    handles.push(join_handle);

    let nns_url = vec![cli_args.canister_url.unwrap_or(cli_args.nns_url)];

    let canister_updater_loop = canister_updater_loop::canister_updater_loop(
        log.clone(),
        ic_discovery.clone(),
        stop_signal_rcv.clone(),
        update_signal_rcv.clone(),
        NodeStatusCanister::new(nns_url, cli_args.canister_id.parse().unwrap()),
        rt.handle().clone(),
        Client::try_from(cli_args.prometheus_url.as_str())?,
    );
    info!(log, "Spawning canister updater thread");
    let canister_join_handle = std::thread::spawn(canister_updater_loop);
    handles.push(canister_join_handle);

    rt.block_on(shutdown_signal);

    for _ in &handles {
        stop_signal_sender.send(())?;
    }

    for handle in handles {
        handle.join().expect("Join failed");
    }

    Ok(())
}

#[derive(Parser, Debug)]
#[clap(about, version)]
pub struct CliArgs {
    #[clap(
        long = "targets-dir",
        help = r#"
A writeable directory where the registries of the targeted Internet Computer
instances are stored.

If the directory does not contain a directory called 'mercury' and
`--no-mercury` is *not* specified, a corresponding target will be generated and
initialized with a hardcoded initial registry.

"#
    )]
    targets_dir: PathBuf,

    #[clap(
    long = "poll-interval",
    default_value = "10s",
    value_parser = parse_duration,
    help = r#"
The interval at which ICs are polled for updates.

"#
    )]
    poll_interval: Duration,

    #[clap(
    long = "query-request-timeout",
    default_value = "5s",
    value_parser = parse_duration,
    help = r#"
The HTTP-request timeout used when querying for registry updates.

"#
    )]
    registry_query_timeout: Duration,

    #[clap(
        long = "nns-url",
        default_value = "https://ic0.app",
        help = r#"
NNS-url to use for syncing the registry version.
"#
    )]
    nns_url: Url,

    #[clap(
        long = "skip-sync",
        help = r#"
If specified to true the local version of registry will be used.
Possible only if the version is not a ZERO_REGISTRY_VERSION
"#
    )]
    skip_sync: bool,

    #[clap(
        long = "canister-url",
        help = r#"
NNS-url to use for canisters.
"#
    )]
    canister_url: Option<Url>,

    #[clap(
        long = "canister-id",
        help = r#"
Canister id of NodeStatusCanister.
"#
    )]
    canister_id: String,

    #[clap(
        long = "prometheus-url",
        default_value = "https://prometheus.mainnet.dfinity.network",
        help = r#"
NNS-url to use for syncing the registry version.
"#
    )]
    prometheus_url: Url,
}

impl CliArgs {
    fn validate(self) -> Result<Self> {
        if !self.targets_dir.exists() {
            bail!("Path does not exist: {:?}", self.targets_dir);
        }

        if !self.targets_dir.is_dir() {
            bail!("Not a directory: {:?}", self.targets_dir);
        }

        if self.canister_id.parse::<Principal>().is_err() {
            bail!("Invalid canister id: {:?}", self.canister_id);
        }

        Ok(self)
    }
}
