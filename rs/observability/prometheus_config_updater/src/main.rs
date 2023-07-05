use std::net::SocketAddr;
use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{bail, Result};
use clap::Parser;
use config_writer_common::config_writer::ConfigWriter;
use config_writer_common::filters::{NodeIDRegexFilter, TargetGroupFilter, TargetGroupFilterList};
use futures_util::FutureExt;
use humantime::parse_duration;
use ic_async_utils::shutdown_signal;
use ic_config::metrics::{Config as MetricsConfig, Exporter};
use ic_crypto_utils_threshold_sig_der::parse_threshold_sig_key_from_der;
use ic_http_endpoints_metrics::MetricsHttpEndpoint;
use ic_metrics::MetricsRegistry;
use regex::Regex;
use service_discovery::registry_sync::sync_local_registry;
use service_discovery::{metrics::Metrics, poll_loop::make_poll_loop, IcServiceDiscoveryImpl};
use slog::{info, o, Drain, Logger};
use url::Url;

use crate::custom_filters::OldMachinesFilter;
use crate::prometheus_config::PrometheusConfigBuilder;

mod custom_filters;
mod jobs;
mod prometheus_config;
// mod prometheus_updater;

#[derive(Clone, Debug)]
pub struct JobParameters {
    pub port: u16,
    pub endpoint: String,
}

fn main() -> Result<()> {
    let cli_args = CliArgs::parse().validate()?;
    let public_key = cli_args.public_key.map(|pk: String| {
        let decoded = base64::decode(&pk).unwrap();

        parse_threshold_sig_key_from_der(&decoded)
            .map_err(|e| anyhow::format_err!("Failed to get nns_public_key: {}", e))
            .unwrap()
    });
    let nns_urls = cli_args
        .nns_urls
        .split(',')
        .map(Url::parse)
        .collect::<Result<Vec<Url>, _>>()?;
    let rt = tokio::runtime::Runtime::new()?;
    let log = make_logger();
    let metrics_registry = MetricsRegistry::new();
    let shutdown_signal = shutdown_signal(log.clone()).shared();
    let mut handles = vec![];

    info!(log, "Starting prometheus-config-updater");
    let mercury_dir = cli_args.targets_dir.join(cli_args.ic_name);

    rt.block_on(sync_local_registry(
        log.clone(),
        mercury_dir,
        nns_urls,
        cli_args.skip_sync,
        public_key,
    ));

    let jobs = jobs::get_jobs();

    info!(log, "Starting IcServiceDiscovery ...");
    let ic_discovery = Arc::new(IcServiceDiscoveryImpl::new(
        log.clone(),
        cli_args.targets_dir,
        cli_args.registry_query_timeout,
        jobs,
    )?);

    let metrics = Metrics::new(metrics_registry.clone());
    info!(
        log,
        "Metrics are exposed on {}.", cli_args.metrics_listen_addr
    );
    let exporter_config = MetricsConfig {
        exporter: Exporter::Http(cli_args.metrics_listen_addr),
        ..Default::default()
    };
    let _metrics_endpoint = MetricsHttpEndpoint::new_insecure(
        rt.handle().clone(),
        exporter_config,
        metrics_registry,
        &log,
    );

    let (stop_signal_sender, stop_signal_rcv) = crossbeam::channel::bounded::<()>(0);
    let (update_signal_sender, update_signal_rcv) = crossbeam::channel::bounded::<()>(0);
    let loop_fn = make_poll_loop(
        log.clone(),
        rt.handle().clone(),
        ic_discovery.clone(),
        stop_signal_rcv.clone(),
        cli_args.poll_interval,
        metrics.clone(),
        Some(update_signal_sender),
        2,
    );
    let join_handle = std::thread::spawn(loop_fn);
    handles.push(join_handle);
    info!(
        log,
        "Scraping thread spawned. Interval: {:?}", cli_args.poll_interval
    );

    let mut filters_vec: Vec<Box<dyn TargetGroupFilter>> = vec![];
    if let Some(filter_node_id_regex) = &cli_args.filter_node_id_regex {
        filters_vec.push(Box::new(NodeIDRegexFilter::new(
            filter_node_id_regex.clone(),
        )));
    };

    // We need to filter old nodes for host node exporters, but not for everything else
    // To do that, we will create 2 separate updated nodes, with different filters for them
    let jobs = vec![
        jobs::JOB_NODE_EXPORTER_GUEST,
        jobs::JOB_ORCHESTRATOR,
        jobs::JOB_REPLICA,
    ];

    let filters = Arc::new(TargetGroupFilterList::new(filters_vec));
    let config_updater_loop = config_writer_common::config_updater_loop::config_updater_loop(
        log.clone(),
        ic_discovery.clone(),
        filters.clone(),
        stop_signal_rcv.clone(),
        jobs,
        update_signal_rcv.clone(),
        PrometheusConfigBuilder::new(),
        ConfigWriter::new(cli_args.generation_dir.clone(), filters, log.clone()),
        metrics.clone(),
    );
    let config_join_handle = std::thread::spawn(config_updater_loop);
    handles.push(config_join_handle);

    // creating the filters vector again because of ownership
    let mut filters_vec: Vec<Box<dyn TargetGroupFilter>> = vec![];
    if let Some(filter_node_id_regex) = &cli_args.filter_node_id_regex {
        filters_vec.push(Box::new(NodeIDRegexFilter::new(
            filter_node_id_regex.clone(),
        )));
    };
    // Second loop, with the old machines filter
    let jobs = vec![jobs::JOB_NODE_EXPORTER_HOST];

    filters_vec.push(Box::new(OldMachinesFilter {}));

    let filters = Arc::new(TargetGroupFilterList::new(filters_vec));
    let config_updater_loop = config_writer_common::config_updater_loop::config_updater_loop(
        log.clone(),
        ic_discovery,
        filters.clone(),
        stop_signal_rcv,
        jobs,
        update_signal_rcv,
        PrometheusConfigBuilder::new(),
        ConfigWriter::new(cli_args.generation_dir, filters, log.clone()),
        metrics,
    );
    let config_join_handle = std::thread::spawn(config_updater_loop);
    handles.push(config_join_handle);

    rt.block_on(shutdown_signal);

    for _ in &handles {
        stop_signal_sender.send(())?;
    }

    for handle in handles {
        handle.join().expect("Join of a handle failed");
    }
    Ok(())
}

fn make_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).chan_size(8192).build();
    slog::Logger::root(drain.fuse(), o!())
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
    parse(try_from_str = parse_duration),
    help = r#"
The interval at which ICs are polled for updates.

"#
    )]
    poll_interval: Duration,

    #[clap(
    long = "query-request-timeout",
    default_value = "5s",
    parse(try_from_str = parse_duration),
    help = r#"
The HTTP-request timeout used when quering for registry updates.

"#
    )]
    registry_query_timeout: Duration,

    #[clap(
        long = "generation-dir",
        help = r#"
If specified, for each job, a json file containing the targets will be written
to <generation_dir>/<job_name>.json containing the corresponding
targets.

"#
    )]
    generation_dir: PathBuf,

    #[clap(
        long = "filter-node-id-regex",
        help = r#"
Regex used to filter the node IDs

"#
    )]
    filter_node_id_regex: Option<Regex>,

    #[clap(
        long = "ic-name",
        default_value = "mercury",
        help = r#"
IC-name for labelling target nodes.
"#
    )]
    ic_name: String,

    #[clap(
        long = "nns-urls",
        default_value = "https://ic0.app",
        help = r#"
NNS-urls to use for syncing the registry version.
"#
    )]
    nns_urls: String,

    #[clap(
        long = "skip-sync",
        help = r#"
If specified to true the local version of registry will be used.
Possible only if the version is not a ZERO_REGISTRY_VERSION
"#
    )]
    skip_sync: bool,

    #[clap(
        long = "public_key",
        help = r#"
If specified the public key for validating nns registry base64 encoded one line
"#
    )]
    public_key: Option<String>,

    #[clap(
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

        if !self.generation_dir.is_dir() {
            bail!("Not a directory: {:?}", self.generation_dir)
        }

        Ok(self)
    }
}
