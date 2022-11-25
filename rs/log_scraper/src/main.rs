use std::collections::HashMap;
use std::{fs::OpenOptions, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use crate::log_scraper::scrape_logs;
use anyhow::{bail, Result};
use clap::Parser;
use futures_util::FutureExt;
use humantime::parse_duration;
use ic_async_utils::shutdown_signal;
use ic_config::metrics::Config as MetricsConfig;
use ic_config::metrics::Exporter;
use ic_http_endpoints_metrics::MetricsHttpEndpoint;
use ic_metrics::MetricsRegistry;
use service_discovery::config_generator::ConfigGenerator;
use service_discovery::{
    file_sd::FileSd,
    mainnet_registry::{create_local_store_from_changelog, get_mainnet_delta_6d_c1},
    metrics::Metrics,
    poll_loop::make_poll_loop,
    rest_api::start_http_server,
};
use service_discovery::{IcServiceDiscovery, IcServiceDiscoveryImpl};
use slog::{info, o, Drain, Logger};

mod log_scraper;

pub const NODE_EXPORTER: &str = "node_exporter";

fn main() -> Result<()> {
    let cli_args = CliArgs::parse().validate()?;
    let rt = tokio::runtime::Runtime::new()?;
    let log = make_logger();
    let metrics_registry = MetricsRegistry::new();
    let shutdown_signal = shutdown_signal(log.clone()).shared();

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

    let file_sd = if let Some(file_sd_base_path) = &cli_args.file_sd_base_path {
        info!(
            log,
            "Writing service discovery files to base dir: {:?}", file_sd_base_path
        );
        let file_sd = FileSd::new(file_sd_base_path);
        for job_name in get_jobs()
            .into_iter()
            .map(|(job, _)| job)
            .collect::<Vec<&str>>()
        {
            let targets = ic_discovery.get_target_groups(job_name)?;
            file_sd.write_sd_config(job_name, targets)?;
        }
        Some(Box::new(file_sd) as Box<dyn ConfigGenerator>)
    } else {
        None
    };

    let http_handle = cli_args.listen_addr.map(|listen_addr| {
        info!(log, "Starting REST API ...");
        rt.spawn(start_http_server(
            log.clone(),
            ic_discovery.clone(),
            listen_addr,
            shutdown_signal.clone(),
        ))
    });

    let (stop_signal_sender, stop_signal_rcv) = crossbeam::channel::bounded::<()>(0);
    let poll_loop = make_poll_loop(
        log.clone(),
        rt.handle().clone(),
        ic_discovery.clone(),
        stop_signal_rcv,
        cli_args.poll_interval,
        Metrics::new(metrics_registry.clone()),
        file_sd,
        get_jobs().into_iter().map(|(job, _)| job).collect(),
    );

    info!(
        log,
        "Spawning scraping thread. Interval: {:?}", cli_args.poll_interval
    );
    let join_handle = std::thread::spawn(poll_loop);

    let log_scrape_handle = if let Some(journal_file_path) = cli_args.gatewayd_logs_path {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(journal_file_path)
            .expect("Could not open file.");
        Some(rt.spawn(scrape_logs(
            log.clone(),
            ic_discovery,
            cli_args.gatewayd_logs_target_filter,
            file,
            shutdown_signal.clone(),
            NODE_EXPORTER,
        )))
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
    let metrics_endpoint = MetricsHttpEndpoint::new_insecure(
        rt.handle().clone(),
        exporter_config,
        metrics_registry,
        &log,
    );

    rt.block_on(shutdown_signal);
    if let Some(http_handle) = http_handle {
        let _ = rt.block_on(http_handle)?;
    }
    if let Some(log_scrape_handle) = log_scrape_handle {
        rt.block_on(log_scrape_handle)?;
    }

    std::mem::drop(metrics_endpoint);

    stop_signal_sender.send(())?;
    join_handle.join().expect("join() failed.");

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
        long = "listen-addr",
        help = r#"
The listen address for service discovery.

"#
    )]
    listen_addr: Option<SocketAddr>,

    #[clap(
        long = "file-sd-base-path",
        help = r#"
If specified, for each job, a json file containing the targets will be written
to <base_directory>/<job_name>/ic_p8s_sd.json containing the corresponding
targets.

"#
    )]
    file_sd_base_path: Option<PathBuf>,

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
        long = "scrape-journal-gatewayd-logs",
        help = r#"
If specified, scrape logs from targets and write all logs to the given file. The
logs are scraped from the endpoint exposed by the systemd-journal-gatewayd
service.

https://www.freedesktop.org/software/systemd/man/systemd-journal-gatewayd.service.html
        
"#
    )]
    gatewayd_logs_path: Option<PathBuf>,
}

impl CliArgs {
    fn validate(self) -> Result<Self> {
        if !self.targets_dir.exists() {
            bail!("Path does not exist: {:?}", self.targets_dir);
        }

        if !self.targets_dir.is_dir() {
            bail!("Not a directory: {:?}", self.targets_dir);
        }

        if let Some(file_sd_base_path) = &self.file_sd_base_path {
            if !file_sd_base_path.is_dir() {
                bail!("Not a directory: {:?}", file_sd_base_path);
            }
        }

        if let Some(gatewayd_logs_path) = &self.gatewayd_logs_path {
            let parent_dir = gatewayd_logs_path.parent().unwrap();
            if !parent_dir.is_dir() {
                bail!("Directory does not exist: {:?}", parent_dir);
            }
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

fn get_jobs() -> HashMap<&'static str, u16> {
    let mut x: HashMap<&str, u16> = HashMap::new();

    x.insert(NODE_EXPORTER, 9100);

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
