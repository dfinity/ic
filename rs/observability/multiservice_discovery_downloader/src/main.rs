use std::{fmt, path::PathBuf, str::FromStr, time::Duration};

use clap::Parser;
use downloader_loop::run_downloader_loop;
use futures_util::FutureExt;
use humantime::parse_duration;
use ic_async_utils::shutdown_signal;
use regex::Regex;
use slog::{info, o, Drain, Logger};
use tokio::runtime::Runtime;
use url::Url;

mod downloader_loop;

fn main() {
    let logger = make_logger();
    let rt = Runtime::new().unwrap();
    let shutdown_signal = shutdown_signal(logger.clone()).shared();
    let cli_args = CliArgs::parse();
    let (stop_signal_sender, stop_signal_rcv) = crossbeam::channel::bounded::<()>(0);

    info!(logger, "Starting downloader loop"; "cli_args" => ?cli_args);

    let downloader_handle = rt.spawn(run_downloader_loop(
        logger.clone(),
        cli_args,
        stop_signal_rcv,
    ));

    rt.block_on(shutdown_signal);
    info!(logger, "Received shutdown signal, shutting down ...");

    stop_signal_sender.send(()).unwrap();

    let _ = rt.block_on(downloader_handle);
}

fn make_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).chan_size(8192).build();
    Logger::root(drain.fuse(), o!())
}

#[derive(Parser, Debug)]
#[clap(about, version)]
pub struct CliArgs {
    #[clap(
        long = "output-dir",
        help = r#"
A writeable directory where the outptu of the targeted Internet Computer
instances are stored.
"#
    )]
    pub output_dir: PathBuf,

    #[clap(
    long = "poll-interval",
    default_value = "30s",
    value_parser = parse_duration,
    help = r#"
The interval at which targets are polled for updates.

"#
    )]
    pub poll_interval: Duration,

    #[clap(
    long = "query-request-timeout",
    default_value = "15s",
    value_parser = parse_duration,
    help = r#"
The HTTP-request timeout used when quering for registry updates.

"#
    )]
    pub registry_query_timeout: Duration,

    #[clap(
        long = "sd-url",
        help = r#"
Service Discovery url to use for syncing the targets.
"#
    )]
    pub sd_url: Url,

    #[clap(
        long = "generator",
        help = r#"
Specify the generator to use for generating the config files.
Currently supported values:
- 1. log -> will generate vector config
- 2. metric -> will generate prometheus config
    "#
    )]
    generator: Generator,

    #[clap(
        long = "filter-node-id-regex",
        help = r#"
Regex used to filter the node IDs

"#
    )]
    filter_node_id_regex: Option<Regex>,

    #[clap(
        long = "filter-ic-name-regex",
        help = r#"
Regex used to filter the ic name

"#
    )]
    filter_ic_name_regex: Option<Regex>,

    #[clap(
        long = "bn-source-port",
        help = r#"
Custom port for boundary nodes

"#
    )]
    bn_source_port: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum Generator {
    Log,
    Metric,
}

impl FromStr for Generator {
    type Err = GeneratorParserError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "log" => Ok(Generator::Log),
            "metric" => Ok(Generator::Metric),
            _ => Err(GeneratorParserError {
                input: s.to_string(),
            }),
        }
    }
}

#[derive(Debug)]
pub struct GeneratorParserError {
    input: String,
}
impl std::error::Error for GeneratorParserError {}

impl fmt::Display for GeneratorParserError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Could not parse {} into a generator type", self.input)
    }
}
