use std::{path::PathBuf, time::Duration};

use clap::{ArgAction, Parser};
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
        long = "filter-sns-name-regex",
        help = r#"
Regex used to filter the sns name

"#
    )]
    filter_sns_name_regex: Option<Regex>,

    #[clap(long = "script-path", help = "Path for the script file")]
    script_path: String,

    #[clap(long = "cursors-folder", help = "Path for cursors")]
    cursors_folder: String,

    #[clap(
                long = "restart-on-exit",
                help = "Restart on respawn",
                action = ArgAction::SetTrue,
                default_value = "false"
            )]
    restart_on_exit: bool,

    #[clap(long = "include-stderr", help = "Include stderr", action = ArgAction::SetTrue, default_value = "false")]
    include_stderr: bool,
}
