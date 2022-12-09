use std::collections::HashMap;
use std::vec;
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use crate::config_writer_loop::config_writer_loop;
use anyhow::{bail, Result};
use clap::Parser;
use futures_util::FutureExt;
use humantime::parse_duration;
use ic_async_utils::shutdown_signal;
use ic_config::metrics::Config as MetricsConfig;
use ic_config::metrics::Exporter;
use ic_http_endpoints_metrics::MetricsHttpEndpoint;
use ic_metrics::MetricsRegistry;
use service_discovery::job_types::{JobType, NodeOS};
use service_discovery::IcServiceDiscoveryImpl;
use service_discovery::{
    mainnet_registry::{create_local_store_from_changelog, get_mainnet_delta_6d_c1},
    metrics::Metrics,
    poll_loop::make_poll_loop,
};
use slog::{info, o, Drain, Logger};

mod config_writer;
mod config_writer_loop;
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
    // Unless the user does *not* want to target mercury and the respective
    // directory does not already exist, create the target directory and store
    // the mercury registry in there ...
    if !mercury_dir.is_dir() {
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
        get_jobs(),
    )?);

    let (stop_signal_sender, stop_signal_rcv) = crossbeam::channel::bounded::<()>(0);
    let (update_signal_sender, update_signal_rcv) = crossbeam::channel::bounded::<()>(0);
    let poll_loop = make_poll_loop(
        log.clone(),
        rt.handle().clone(),
        ic_discovery.clone(),
        stop_signal_rcv.clone(),
        cli_args.poll_interval,
        Metrics::new(metrics_registry.clone()),
        Some(update_signal_sender),
    );

    info!(
        log,
        "Spawning scraping thread. Interval: {:?}", cli_args.poll_interval
    );
    let join_handle = std::thread::spawn(poll_loop);
    handles.push(join_handle);

    let config_generator_loop = config_writer_loop(
        log.clone(),
        ic_discovery,
        cli_args.gatewayd_logs_target_filter,
        stop_signal_rcv,
        JobType::NodeExporter(NodeOS::Guest),
        update_signal_rcv,
        cli_args.vector_config_dir,
    );
    info!(log, "Spawning config generator thread.");
    let config_join_handle = std::thread::spawn(config_generator_loop);
    handles.push(config_join_handle);

    info!(
        log,
        "Metrics are exposed on {}.", cli_args.metrics_listen_addr
    );
    let exporter_config = MetricsConfig {
        exporter: Exporter::Http(cli_args.metrics_listen_addr),
        ..Default::default()
    };
    let metrics_endpoint = MetricsHttpEndpoint::new_insecure(
        rt.handle().clone(),
        exporter_config,
        metrics_registry,
        &log,
    );

    rt.block_on(shutdown_signal);

    std::mem::drop(metrics_endpoint);

    for handle in handles {
        stop_signal_sender.send(())?;
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
        long = "metrics-listen-addr",
        default_value = "[::]:9099",
        help = r#"
The listen address on which metrics for this service should be exposed.

"#
    )]
    metrics_listen_addr: SocketAddr,

    #[clap(
        long = "logs-target-filter",
        help = r#"
A filter of the format `<key>=<value>`. If specified and --pull-gatewayd-logs is
specified, the given filter is applied to the list of targets from which to pull
logs.

Example:
  --gatewayd-logs-target-filter node_id=n76p6-epjz2-5ensc-gwvgv-niomg-4v3mb-rj4rr-nek67-g7hez-wlv6q-vqe

  Filters the list of targets used for scraping logs.

"#
    )]
    gatewayd_logs_target_filter: Option<String>,

    #[clap(
        long = "generation-dir",
        help = r#"
If specified, generate vector config based on the service discovery to the specified 
directory.

https://www.freedesktop.org/software/systemd/man/systemd-journal-gatewayd.service.html
        
"#
    )]
    vector_config_dir: PathBuf,
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

        if let Some(log_filter) = &self.gatewayd_logs_target_filter {
            check_logs_filter_format(log_filter)?;
        }

        Ok(self)
    }
}

fn check_logs_filter_format(log_filter: &str) -> Result<()> {
    let items = log_filter.split('=').collect::<Vec<_>>();
    if items.len() != 2 {
        bail!("Invalid filter {:?}", log_filter);
    }

    let key = items[0];
    if !(key == "node_id" || key == "subnet_id") {
        bail!(
            "A filter must be of the form node_id=<> or subnet_id=<>: {:?}",
            log_filter
        );
    }

    Ok(())
}

fn get_jobs() -> HashMap<JobType, u16> {
    let mut x: HashMap<JobType, u16> = HashMap::new();

    x.insert(JobType::NodeExporter(NodeOS::Guest), 9100);

    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correct_filter_is_accepted() {
        check_logs_filter_format(
            "node_id=25p5a-3yzir-ifqqt-5lggj-g4nxg-v2qe2-vxw57-qkxtd-wjohn-kfbfp-bqe",
        )
        .unwrap()
    }
}
