use std::net::SocketAddr;
use std::vec;
use std::{path::PathBuf, sync::Arc, time::Duration};

use crate::vector_config_structure::VectorConfigBuilderImpl;
use anyhow::{bail, Result};
use clap::Parser;
use config_writer_common::config_writer_loop::config_writer_loop;
use config_writer_common::filters::{NodeIDRegexFilter, TargetGroupFilter, TargetGroupFilterList};
use futures_util::FutureExt;
use humantime::parse_duration;
use ic_async_utils::shutdown_signal;
use ic_config::metrics::{Config as MetricsConfig, Exporter};
use ic_http_endpoints_metrics::MetricsHttpEndpoint;
use ic_metrics::MetricsRegistry;
use regex::Regex;
use service_discovery::job_types::{map_jobs, JobAndPort};
use service_discovery::registry_sync::sync_local_registry;
use service_discovery::IcServiceDiscoveryImpl;
use service_discovery::{metrics::Metrics, poll_loop::make_poll_loop};
use slog::{info, o, Drain, Logger};
use url::Url;

mod vector_config_structure;

fn main() -> Result<()> {
    let cli_args = CliArgs::parse().validate()?;
    let rt = tokio::runtime::Runtime::new()?;
    let log = make_logger();
    let metrics_registry = MetricsRegistry::new();
    let shutdown_signal = shutdown_signal(log.clone()).shared();
    let mut handles = vec![];

    info!(log, "Starting mercury ...");
    let mercury_dir = cli_args.targets_dir.join("mercury");
    let nns_url = vec![cli_args.nns_url];
    rt.block_on(sync_local_registry(
        log.clone(),
        mercury_dir,
        nns_url,
        cli_args.skip_sync,
        None,
    ));

    info!(log, "Starting IcServiceDiscovery ...");
    info!(log, "Started jobs: {:?}", cli_args.jobs_and_ports);
    let ic_discovery = Arc::new(IcServiceDiscoveryImpl::new(
        log.clone(),
        cli_args.targets_dir,
        cli_args.registry_query_timeout,
        map_jobs(&cli_args.jobs_and_ports),
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

    let mut filters_vec: Vec<Box<dyn TargetGroupFilter>> = vec![];
    if let Some(filter_node_id_regex) = &cli_args.filter_node_id_regex {
        filters_vec.push(Box::new(NodeIDRegexFilter::new(
            filter_node_id_regex.clone(),
        )));
    };

    let filters = Arc::new(TargetGroupFilterList::new(filters_vec));

    let config_generator_loop = config_writer_loop(
        log.clone(),
        ic_discovery,
        filters,
        stop_signal_rcv,
        map_jobs(&cli_args.jobs_and_ports).into_keys().collect(),
        update_signal_rcv,
        cli_args.vector_config_dir,
        VectorConfigBuilderImpl::new(cli_args.batch_size),
        metrics,
    );
    info!(log, "Spawning config generator thread.");
    let config_join_handle = std::thread::spawn(config_generator_loop);
    handles.push(config_join_handle);

    rt.block_on(shutdown_signal);

    for _ in &handles {
        stop_signal_sender.send(())?;
    }

    for handle in handles {
        handle.join().expect("Join failed");
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
The HTTP-request timeout used when quering for registry updates.

"#
    )]
    registry_query_timeout: Duration,

    #[clap(
        long = "filter-node-id-regex",
        help = r#"
Regex used to filter the node IDs

"#
    )]
    filter_node_id_regex: Option<Regex>,

    #[clap(
        long = "generation-dir",
        help = r#"
If specified, generate vector config based on the service discovery to the specified 
directory.

https://www.freedesktop.org/software/systemd/man/systemd-journal-gatewayd.service.html
        
"#
    )]
    vector_config_dir: PathBuf,

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
        long = "batch-size",
        help = r#"
Batch size for generated sources. It represents the amount of log lines before 
persisting the cursor. Default value is 32
        "#,
        default_value = "32"
    )]
    batch_size: u64,

    #[clap(
        long = "metrics-listen-addr",
        default_value = "[::]:9099",
        help = r#"
The listen address on which metrics for this service should be exposed.

"#
    )]
    metrics_listen_addr: SocketAddr,

    #[clap(
        long = "jobs-and-ports",
        value_delimiter = ',',
        help = r#"
Pass the jobs through cli using comma separated values of tuples of (<name>,<port>)
--jobs-and-ports host_node_exporter,9100 --jobs-and-ports node_exporter,9100
"#
    )]
    jobs_and_ports: Vec<JobAndPort>,
}

impl CliArgs {
    fn validate(self) -> Result<Self> {
        if !self.targets_dir.exists() {
            bail!("Path does not exist: {:?}", self.targets_dir);
        }

        if !self.targets_dir.is_dir() {
            bail!("Not a directory: {:?}", self.targets_dir);
        }

        let parent_dir = self.vector_config_dir.parent().unwrap();
        if !parent_dir.is_dir() {
            bail!("Directory does not exist: {:?}", parent_dir);
        }

        if self.jobs_and_ports.is_empty() {
            bail!("No jobs provided...");
        }

        Ok(self)
    }
}
