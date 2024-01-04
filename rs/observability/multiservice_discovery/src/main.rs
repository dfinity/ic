use std::time::Duration;
use std::{path::PathBuf, sync::Arc};

use clap::Parser;
use futures_util::FutureExt;
use humantime::parse_duration;
use slog::{o, Drain, Logger};
use tokio::runtime::Runtime;
use tokio::sync::oneshot::{self};
use tokio::sync::Mutex;
use url::Url;

use definition::{wrap, Definition};
use ic_async_utils::shutdown_signal;

use crate::server_handlers::prepare_server;

mod definition;
mod server_handlers;

fn main() {
    let rt = Runtime::new().unwrap();
    let log = make_logger();
    let shutdown_signal = shutdown_signal(log.clone()).shared();
    let cli_args = CliArgs::parse();
    let mut handles = vec![];
    let mut definitions = vec![];

    let (oneshot_sender, oneshot_receiver) = oneshot::channel();
    if !cli_args.start_without_mainnet {
        let mainnet_definition = get_mainnet_definition(&cli_args, log.clone());
        definitions.push(mainnet_definition.clone());

        let ic_handle = std::thread::spawn(wrap(mainnet_definition, rt.handle().clone()));
        handles.push(ic_handle);
    }
    let definitions = Arc::new(Mutex::new(definitions));
    let handles = Arc::new(Mutex::new(handles));

    //Configure server
    let server_handle = rt.spawn(prepare_server(
        oneshot_receiver,
        log.clone(),
        definitions.clone(),
        cli_args,
        handles.clone(),
        rt.handle().clone(),
    ));

    rt.block_on(shutdown_signal);
    //Stop the server
    oneshot_sender.send(()).unwrap();

    let mut handles = rt.block_on(handles.lock());

    for definition in rt.block_on(definitions.lock()).iter() {
        definition.stop_signal_sender.send(()).unwrap();
    }

    while let Some(handle) = handles.pop() {
        handle.join().unwrap();
    }

    rt.block_on(server_handle).unwrap();
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
        long = "targets-dir",
        help = r#"
A writeable directory where the registries of the targeted Internet Computer
instances are stored.

Mainnet (mercury) directory will be created and initialized if no --start-without-mainnet
is provided.

"#
    )]
    targets_dir: PathBuf,

    #[clap(
    long = "poll-interval",
    default_value = "30s",
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
        long = "nns-url",
        default_value = "https://ic0.app",
        help = r#"
NNS-url to use for syncing the registry version.
"#
    )]
    nns_url: Url,

    #[clap(
        long = "start-without-mainnet",
        default_value = "false",
        action,
        help = r#"
Start the discovery without the IC Mainnet target.
"#
    )]
    start_without_mainnet: bool,
}

fn get_mainnet_definition(cli_args: &CliArgs, log: Logger) -> Definition {
    let (ic_stop_signal_sender, ic_stop_signal_rcv) = crossbeam::channel::bounded::<()>(0);

    Definition::new(
        vec![cli_args.nns_url.clone()],
        cli_args.targets_dir.clone(),
        "mercury".to_string(),
        log.clone(),
        None,
        cli_args.poll_interval,
        ic_stop_signal_rcv,
        cli_args.registry_query_timeout,
        ic_stop_signal_sender,
    )
}
