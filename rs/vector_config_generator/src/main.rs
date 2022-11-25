use std::collections::HashMap;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{bail, Result};
use clap::Parser;
use config_writer::ConfigWriter;
use futures_util::FutureExt;
use humantime::parse_duration;
use ic_async_utils::shutdown_signal;
use ic_config::metrics::{Config as MetricsConfig, Exporter};
use ic_http_endpoints_metrics::MetricsHttpEndpoint;
use ic_metrics::MetricsRegistry;
use regex::Regex;
use service_discovery::{
    config_generator::ConfigGenerator,
    mainnet_registry::{create_local_store_from_changelog, get_mainnet_delta_6d_c1},
    metrics::Metrics,
    poll_loop::make_poll_loop,
    IcServiceDiscoveryImpl, HOST_NODE_EXPORTER_JOB_NAME, NODE_EXPORTER_JOB_NAME,
    ORCHESTRATOR_JOB_NAME, REPLICA_JOB_NAME,
};
use slog::{info, o, Drain, Logger};

use crate::config_writer::{NodeIDRegexFilter, TargetGroupFilter, TargetGroupFilterList};

mod config_writer;
mod vector_configuration;

// TODO Change jobs to make them an enum
fn get_jobs() -> HashMap<&'static str, u16> {
    let mut x: HashMap<&str, u16> = HashMap::new();
    x.insert(NODE_EXPORTER_JOB_NAME, 9100);
    x.insert(HOST_NODE_EXPORTER_JOB_NAME, 9100);
    x.insert(ORCHESTRATOR_JOB_NAME, 9091);
    x.insert(REPLICA_JOB_NAME, 9090);
    x
}

fn main() -> Result<()> {
    let cli_args = CliArgs::parse().validate()?;
    let rt = tokio::runtime::Runtime::new()?;
    let log = make_logger();
    let metrics_registry = MetricsRegistry::new();
    let shutdown_signal = shutdown_signal(log.clone()).shared();

    info!(log, "Starting vector-config-generator");
    let mercury_dir = cli_args.targets_dir.join("mercury");
    let _store = create_local_store_from_changelog(mercury_dir, get_mainnet_delta_6d_c1());

    let jobs = get_jobs();

    info!(log, "Starting IcServiceDiscovery ...");
    let ic_discovery = Arc::new(IcServiceDiscoveryImpl::new(
        cli_args.targets_dir,
        cli_args.registry_query_timeout,
        jobs.clone(),
    )?);

    let mut filters_vec: Vec<Box<dyn TargetGroupFilter>> = vec![];
    if let Some(filter_node_id_regex) = &cli_args.filter_node_id_regex {
        filters_vec.push(Box::new(NodeIDRegexFilter::new(
            filter_node_id_regex.clone(),
        )));
    };

    let filters = TargetGroupFilterList::new(filters_vec);

    let config_writer = if let Some(generation_dir) = &cli_args.generation_dir {
        let config_writer = ConfigWriter::new(generation_dir, filters);
        Some(Box::new(config_writer) as Box<dyn ConfigGenerator>)
    } else {
        None
    };

    let (stop_signal_sender, stop_signal_rcv) = crossbeam::channel::bounded::<()>(0);
    let loop_fn = make_poll_loop(
        log.clone(),
        rt.handle().clone(),
        ic_discovery,
        stop_signal_rcv,
        cli_args.poll_interval,
        Metrics::new(metrics_registry.clone()),
        config_writer,
        jobs.into_iter().map(|(job, _)| job).collect(),
    );
    let join_handle = std::thread::spawn(loop_fn);
    info!(
        log,
        "Scraping thread spawned. Interval: {:?}", cli_args.poll_interval
    );
    let scrape_handle = Some((stop_signal_sender, join_handle));

    info!(
        log,
        "Metrics are exposed on {}.", cli_args.metrics_listen_addr
    );
    let exporter_config = MetricsConfig {
        exporter: Exporter::Http(cli_args.metrics_listen_addr),
    };
    let metrics_runtime = MetricsHttpEndpoint::new_insecure(
        rt.handle().clone(),
        exporter_config,
        metrics_registry,
        &log,
    );

    rt.block_on(shutdown_signal);
    std::mem::drop(metrics_runtime);

    if let Some((stop_signal_handler, join_handle)) = scrape_handle {
        stop_signal_handler.send(())?;
        join_handle.join().expect("join() failed.");
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
    generation_dir: Option<PathBuf>,

    #[clap(
        long = "metrics-listen-addr",
        default_value = "[::]:9099",
        help = r#"
The listen address on which metrics for this service should be exposed.

"#
    )]
    metrics_listen_addr: SocketAddr,

    #[clap(
        long = "filter-node-id-regex",
        help = r#"
Regex used to filter the node IDs

"#
    )]
    filter_node_id_regex: Option<Regex>,
}
impl CliArgs {
    fn validate(self) -> Result<Self> {
        if !self.targets_dir.exists() {
            bail!("Path does not exist: {:?}", self.targets_dir);
        }

        if !self.targets_dir.is_dir() {
            bail!("Not a directory: {:?}", self.targets_dir);
        }

        if let Some(generation_dir) = &self.generation_dir {
            if !generation_dir.is_dir() {
                bail!("Not a directory: {:?}", generation_dir)
            }
        }

        Ok(self)
    }
}
