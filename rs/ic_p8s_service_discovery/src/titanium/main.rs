use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use crossbeam::select;
use crossbeam_channel::Receiver;
use humantime::parse_duration;
use ic_config::metrics::{Config as MetricsConfig, Exporter};
use ic_metrics::MetricsRegistry;
use ic_metrics_exporter::MetricsRuntimeImpl;
use ic_p8s_service_discovery::titanium::{
    ic_discovery::IcServiceDiscoveryImpl,
    mainnet_registry::{create_local_store_from_changelog, get_mainnet_delta_6d_c1},
    metrics::Metrics,
    rest_api::start_http_server,
};
use slog::{info, o, warn, Drain, Logger};
use structopt::StructOpt;

fn main() -> Result<()> {
    let cli_args = CliArgs::from_args().validate()?;
    let rt = tokio::runtime::Runtime::new()?;
    let log = make_logger();
    let metrics_registry = MetricsRegistry::new();

    info!(log, "Starting ic-p8s-sd ...");
    let mercury_dir = cli_args.targets_dir.join("mercury");
    // Unless the user does *not* want to target mercury and the respective
    // directory does not already exist, create the target directory and store
    // the mercury registry in there ...
    if !cli_args.no_mercury && !mercury_dir.is_dir() {
        info!(
            log,
            "Writing mercury registry up to version 0x6d1c to {:?} ", mercury_dir
        );
        let _store = create_local_store_from_changelog(mercury_dir, get_mainnet_delta_6d_c1());
    }

    info!(log, "Starting IcServiceDiscovery ...");
    let ic_discovery = Arc::new(IcServiceDiscoveryImpl::new(
        cli_args.targets_dir,
        cli_args.registry_query_timeout,
    )?);

    info!(log, "Starting REST API ...");
    let http_handle = rt.spawn(start_http_server(
        log.clone(),
        ic_discovery.clone(),
        cli_args.listen_addr,
    ));

    let scrape_handle = if !cli_args.no_poll {
        let (stop_signal_sender, stop_signal_rcv) = crossbeam::channel::bounded::<()>(0);
        let poll_loop = make_poll_loop(
            log.clone(),
            ic_discovery,
            stop_signal_rcv,
            cli_args.poll_interval,
            Metrics::new(metrics_registry.clone()),
        );

        info!(
            log,
            "Spawning scraping thread. Interval: {:?}", cli_args.poll_interval
        );
        let join_handle = std::thread::spawn(poll_loop);

        Some((stop_signal_sender, join_handle))
    } else {
        None
    };

    info!(
        log,
        "Metrics are exposed on {}.", cli_args.metrics_listen_addr
    );
    let exporter_config = MetricsConfig {
        exporter: Exporter::Http(cli_args.metrics_listen_addr),
    };
    let metrics_runtime = MetricsRuntimeImpl::new_insecure(
        rt.handle().clone(),
        exporter_config,
        metrics_registry,
        &log,
    );

    let _ = rt.block_on(http_handle)?;
    std::mem::drop(metrics_runtime);

    if let Some((stop_signal_handler, join_handle)) = scrape_handle {
        stop_signal_handler.send(())?;
        join_handle.join().expect("join() failed.");
    }
    Ok(())
}

fn make_poll_loop(
    log: slog::Logger,
    ic_discovery: Arc<IcServiceDiscoveryImpl>,
    stop_signal: Receiver<()>,
    poll_interval: Duration,
    metrics: Metrics,
) -> impl Fn() {
    let interval = crossbeam::channel::tick(poll_interval);
    move || {
        let mut tick = Instant::now();
        loop {
            let mut err = false;
            info!(log, "Loading new scraping targets (tick: {:?})", tick);
            if let Err(e) = ic_discovery.load_new_scraping_targets() {
                warn!(
                    log,
                    "Failed to load new scraping targets @ interval {:?}: {:?}", tick, e
                );
                metrics
                    .error_count
                    .with_label_values(&["load_new_scraping_targets"])
                    .inc();
                err = true;
            }
            info!(log, "Update registries");
            let timer = metrics.registries_update_latency_seconds.start_timer();
            if let Err(e) = ic_discovery.update_registries() {
                warn!(
                    log,
                    "Failed to sync registry @ interval {:?}: {:?}", tick, e
                );
                metrics
                    .error_count
                    .with_label_values(&["update_registries"])
                    .inc();
                err = true;
            }
            std::mem::drop(timer);
            let poll_status = if err { "error" } else { "successful" };
            metrics.poll_count.with_label_values(&[poll_status]).inc();
            tick = select! {
                recv(stop_signal) -> _ => return,
                recv(interval) -> msg => msg.expect("tick failed!")
            };
        }
    }
}

fn make_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).chan_size(8192).build();
    slog::Logger::root(drain.fuse(), o!())
}

#[derive(StructOpt, Debug)]
pub struct CliArgs {
    #[structopt(
        long = "targets-dir",
        about = r#"
A writeable directory where the registries of the targeted Internet Computer
instances are stored.

If the directory does not contain a directory called 'mercury' and
`--no-mercury` is *not* specified, a corresponding target will be generated and
initialized with a hardcoded initial registry.

"#
    )]
    targets_dir: PathBuf,

    #[structopt(
        long = "no-mercury",
        about = r#"
Omit initializing the mercury (mainnet) registry if it is not present in the
scraping directory.

"#
    )]
    no_mercury: bool,

    #[structopt(
        long = "no-poll",
        about = r#"
Do not scrape the ICs (i.e. the content of the scraping directory and the served
targets remains unchanged).

"#
    )]
    no_poll: bool,

    #[structopt(
    long = "poll-interval",
    default_value = "10s",
    parse(try_from_str = parse_duration),
    help = r#"
The interval at which ICs are polled for updates.

"#
    )]
    poll_interval: Duration,

    #[structopt(
    long = "query-request-timeout",
    default_value = "5s",
    parse(try_from_str = parse_duration),
    help = r#"
The HTTP-request timeout used when quering for registry updates.

"#
    )]
    registry_query_timeout: Duration,

    #[structopt(
        long = "listen-addr",
        default_value = "[::]:11235",
        help = r#"
The listen address for service discovery.

"#
    )]
    listen_addr: SocketAddr,

    #[structopt(
        long = "metrics-listen-addr",
        default_value = "[::]:9099",
        help = r#"
The listen address on which metrics for this service should be exposed.

"#
    )]
    metrics_listen_addr: SocketAddr,
}
impl CliArgs {
    fn validate(self) -> Result<Self> {
        if !self.targets_dir.exists() {
            bail!("Path does not exist: {:?}", self.targets_dir);
        }

        if !self.targets_dir.is_dir() {
            bail!("Not a directory: {:?}", self.targets_dir);
        }

        Ok(self)
    }
}
